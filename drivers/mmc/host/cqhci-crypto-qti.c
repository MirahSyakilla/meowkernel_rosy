// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020-2021, Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <crypto/algapi.h>
#include "sdhci.h"
#include "sdhci-pltfm.h"
#include "sdhci-msm.h"
#include "cqhci-crypto-qti.h"
#include "../core/queue.h"
#include <linux/crypto-qti-common.h>
#include <linux/pm_runtime.h>
#include <linux/atomic.h>
#include <linux/of.h>
#if IS_ENABLED(CONFIG_CRYPTO_DEV_QCOM_ICE)
#include <crypto/ice.h>
#include <linux/blkdev.h>
#endif

#define RAW_SECRET_SIZE 32
#define MINIMUM_DUN_SIZE 512
#define MAXIMUM_DUN_SIZE 65536
#define QTI_ICE_REG_VERSION 0x0008
#define QTI_ICE_VERSION_MAJOR(version) (((version) >> 24) & 0xff)
#define QTI_ICE_VERSION_MINOR(version) (((version) >> 16) & 0xff)
#define QTI_ICE_VERSION_STEP(version) ((version) & 0xffff)

#define QTI_LEGACY_ICE_V2_PROP "qcom,legacy-ice-v2"
#define QTI_LEGACY_ICE_V2_NUM_KEYSLOTS 30
#define QTI_LEGACY_ICE_V2_KEYSLOT_OFFSET 2
#define QTI_LEGACY_ICE_V2_KSM_DUS 4096
#define QTI_LEGACY_ICE_V2_HW_DUS 512

#define QTI_ICE2_CTRL_INFO_1 0x304
#define QTI_ICE2_CTRL_INFO_2 0x308
#define QTI_ICE2_CTRL_INFO_3 0x30c
#define QTI_ICE2_CTRL_INFO_STRIDE 0x10
#define QTI_ICE2_CTRL_BYPASS BIT(0)
#define QTI_ICE2_CTRL_KEYSLOT_SHIFT 1
#define QTI_ICE2_CTRL_KEYSLOT_MASK 0x1f
#define QTI_ICE2_CTRL_CDU_SHIFT 6
#define QTI_ICE2_CTRL_CDU_MASK 0x7

enum qti_ice2_data_unit {
	QTI_ICE2_DU_512_B,
	QTI_ICE2_DU_1_KB,
	QTI_ICE2_DU_2_KB,
	QTI_ICE2_DU_4_KB,
	QTI_ICE2_DU_8_KB,
	QTI_ICE2_DU_16_KB,
	QTI_ICE2_DU_32_KB,
	QTI_ICE2_DU_64_KB,
};

static void cqhci_crypto_qti_setup_rq_keyslot_manager(
					struct cqhci_host *host,
					struct request_queue *q);
static void cqhci_crypto_qti_destroy_rq_keyslot_manager(
					struct cqhci_host *host,
					struct request_queue *q);

static bool cqhci_crypto_qti_is_legacy_ice_v2(struct cqhci_host *host)
{
	struct sdhci_host *sdhci;
	struct sdhci_pltfm_host *pltfm_host;
	struct sdhci_msm_host *msm_host;

	if (!host || !host->mmc)
		return false;

	sdhci = mmc_priv(host->mmc);
	pltfm_host = sdhci_priv(sdhci);
	msm_host = pltfm_host->priv;

	return msm_host && msm_host->pdev &&
		of_property_read_bool(msm_host->pdev->dev.of_node,
				      QTI_LEGACY_ICE_V2_PROP);
}

static unsigned int cqhci_crypto_qti_hw_keyslot(struct cqhci_host *host,
						 unsigned int slot)
{
	if (cqhci_crypto_qti_is_legacy_ice_v2(host))
		return slot + QTI_LEGACY_ICE_V2_KEYSLOT_OFFSET;

	return slot;
}

static int cqhci_crypto_qti_ice2_config(struct cqhci_host *host,
					struct mmc_request *mrq, u64 lba,
					bool bypass, unsigned int hw_keyslot,
					enum qti_ice2_data_unit cdu)
{
	struct sdhci_host *sdhci = mmc_priv(host->mmc);
	u32 offset;
	u32 ctrl = 0;

	if (WARN_ON(mrq->tag < 0 || mrq->tag >= host->num_slots))
		return -EINVAL;

	offset = mrq->tag * QTI_ICE2_CTRL_INFO_STRIDE;
	ctrl = (hw_keyslot & QTI_ICE2_CTRL_KEYSLOT_MASK) <<
		QTI_ICE2_CTRL_KEYSLOT_SHIFT;
	ctrl |= (cdu & QTI_ICE2_CTRL_CDU_MASK) << QTI_ICE2_CTRL_CDU_SHIFT;
	if (bypass)
		ctrl |= QTI_ICE2_CTRL_BYPASS;

	writel_relaxed(lower_32_bits(lba),
		       sdhci->ioaddr + QTI_ICE2_CTRL_INFO_1 + offset);
	writel_relaxed(upper_32_bits(lba),
		       sdhci->ioaddr + QTI_ICE2_CTRL_INFO_2 + offset);
	writel_relaxed(ctrl,
		       sdhci->ioaddr + QTI_ICE2_CTRL_INFO_3 + offset);

	/* Ensure all per-tag ICE registers are visible before ringing CQDBR. */
	mb();
	return 0;
}

static struct cqhci_host_crypto_variant_ops cqhci_crypto_qti_variant_ops = {
	.setup_rq_keyslot_manager =
		cqhci_crypto_qti_setup_rq_keyslot_manager,
	.destroy_rq_keyslot_manager =
		cqhci_crypto_qti_destroy_rq_keyslot_manager,
	.host_init_crypto = cqhci_crypto_qti_init_crypto,
	.enable = cqhci_crypto_qti_enable,
	.disable = cqhci_crypto_qti_disable,
	.resume = cqhci_crypto_qti_resume,
	.debug = cqhci_crypto_qti_debug,
	.reset = cqhci_crypto_qti_reset,
	.prepare_crypto_desc = cqhci_crypto_qti_prep_desc,
	.recovery_finish = cqhci_crypto_qti_recovery_finish,
};

static atomic_t keycache;
static bool cmdq_use_default_du_size;

static bool ice_cap_idx_valid(struct cqhci_host *host,
					unsigned int cap_idx)
{
	return cap_idx < host->crypto_capabilities.num_crypto_cap;
}

static uint8_t get_data_unit_size_mask(unsigned int data_unit_size)
{
	if (data_unit_size < MINIMUM_DUN_SIZE ||
		data_unit_size > MAXIMUM_DUN_SIZE ||
	    !is_power_of_2(data_unit_size))
		return 0;

	return data_unit_size / MINIMUM_DUN_SIZE;
}


void cqhci_crypto_qti_enable(struct cqhci_host *host)
{
	int err = 0;

	if (!cqhci_host_is_crypto_supported(host) || !host->ksm ||
	    !host->crypto_vops->priv)
		return;

	host->caps |= CQHCI_CAP_CRYPTO_SUPPORT;

	err = crypto_qti_enable(host->crypto_vops->priv);
	if (host->crypto_ice2)
		pr_info("%s: ICE2 enable result=%d caps=0x%x\n",
			__func__, err, host->caps);
	if (err) {
		pr_err("%s: Error enabling crypto, err %d\n",
				__func__, err);
		cqhci_crypto_qti_disable(host);
	}
}

void cqhci_crypto_qti_disable(struct cqhci_host *host)
{
	cqhci_crypto_disable_spec(host);
	if (host->crypto_vops->priv)
		crypto_qti_disable(host->crypto_vops->priv);
}

int cqhci_crypto_qti_reset(struct cqhci_host *host)
{
	atomic_set(&keycache, 0);
	return 0;
}

static int cqhci_crypto_qti_keyslot_program(struct keyslot_manager *ksm,
					    const struct blk_crypto_key *key,
					    unsigned int slot)
{
	struct cqhci_host *host = keyslot_manager_private(ksm);
	int err = 0;
	u8 data_unit_mask, hw_data_unit_mask;
	int crypto_alg_id;
	unsigned int hw_slot;
	struct sdhci_host *sdhci = mmc_priv(host->mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(sdhci);
	struct sdhci_msm_host *msm_host = pltfm_host->priv;

	crypto_alg_id = cqhci_crypto_cap_find(host, key->crypto_mode,
					       key->data_unit_size);

	if (!IS_ERR(msm_host->pclk) && !IS_ERR(msm_host->ice_clk)) {
		err = clk_prepare_enable(msm_host->pclk);
		if (err)
			return err;
		err = clk_prepare_enable(msm_host->ice_clk);
		if (err)
			goto disable_pclk;
	} else {
		pr_err("%s: Invalid clock value\n", __func__);
		return -EINVAL;
	}

	/*
	 * The KSM core already runtime-resumes host->mmc->parent before taking
	 * ksm->lock.  Rosy's ICE2 path must not synchronously resume/suspend the
	 * card again from inside that lock, before the request reaches MMC MQ.
	 */
	if (!host->crypto_ice2)
		pm_runtime_get_sync(&host->mmc->card->dev);

	if (!cqhci_is_crypto_enabled(host) ||
	    !cqhci_keyslot_valid(host, slot) ||
	    !ice_cap_idx_valid(host, crypto_alg_id)) {
		err = -EINVAL;
		goto out;
	}

	data_unit_mask = get_data_unit_size_mask(key->data_unit_size);

	if (!(data_unit_mask &
	      host->crypto_cap_array[crypto_alg_id].sdus_mask)) {
		err = -EINVAL;
		goto out;
	}

	/*
	 * Rosy's legacy ext4 policy presents 4 KiB units to fscrypt, but ICE2
	 * derives the IV from the 512-byte request sector.  Program that legacy
	 * hardware DUS while retaining the 4 KiB KSM contract.
	 */
	hw_data_unit_mask = data_unit_mask;
	if (cqhci_crypto_qti_is_legacy_ice_v2(host) ||
	    cmdq_use_default_du_size)
		hw_data_unit_mask =
			get_data_unit_size_mask(QTI_LEGACY_ICE_V2_HW_DUS);

	hw_slot = cqhci_crypto_qti_hw_keyslot(host, slot);
	err = crypto_qti_keyslot_program(host->crypto_vops->priv, key,
					 hw_slot, hw_data_unit_mask,
					 crypto_alg_id);
	if (err) {
		pr_err("%s: failed to program logical slot %u (hardware %u), error %d\n",
		       __func__, slot, hw_slot, err);
	} else if (host->crypto_ice2) {
		atomic_or(BIT(slot), &keycache);
	}

out:
	if (!host->crypto_ice2)
		pm_runtime_put_sync(&host->mmc->card->dev);
	clk_disable_unprepare(msm_host->ice_clk);
disable_pclk:
	clk_disable_unprepare(msm_host->pclk);
	return err;
}

static int cqhci_crypto_qti_keyslot_evict(struct keyslot_manager *ksm,
					  const struct blk_crypto_key *key,
					  unsigned int slot)
{
	int err = 0;
	int val = 0;
	unsigned int hw_slot;
	struct cqhci_host *host = keyslot_manager_private(ksm);
	struct sdhci_host *sdhci = mmc_priv(host->mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(sdhci);
	struct sdhci_msm_host *msm_host = pltfm_host->priv;

	if (!IS_ERR(msm_host->pclk) && !IS_ERR(msm_host->ice_clk)) {
		err = clk_prepare_enable(msm_host->pclk);
		if (err)
			return err;
		err = clk_prepare_enable(msm_host->ice_clk);
		if (err)
			goto disable_pclk;
	} else {
		pr_err("%s: Invalid clock value\n", __func__);
		return -EINVAL;
	}
	if (!host->crypto_ice2)
		pm_runtime_get_sync(&host->mmc->card->dev);

	if (!cqhci_is_crypto_enabled(host) ||
	    !cqhci_keyslot_valid(host, slot)) {
		err = -EINVAL;
		goto out;
	}

	hw_slot = cqhci_crypto_qti_hw_keyslot(host, slot);
	err = crypto_qti_keyslot_evict(host->crypto_vops->priv, hw_slot);
	if (err)
		pr_err("%s: failed to evict logical slot %u (hardware %u), error %d\n",
		       __func__, slot, hw_slot, err);

out:
	if (!host->crypto_ice2)
		pm_runtime_put_sync(&host->mmc->card->dev);
	clk_disable_unprepare(msm_host->ice_clk);
	if (!err) {
		val = atomic_read(&keycache) & ~BIT(slot);
		atomic_set(&keycache, val);
	}
disable_pclk:
	clk_disable_unprepare(msm_host->pclk);
	return err;
}

static int cqhci_crypto_qti_derive_raw_secret(struct keyslot_manager *ksm,
		const u8 *wrapped_key, unsigned int wrapped_key_size,
		u8 *secret, unsigned int secret_size)
{
	int err = 0;

	err = crypto_qti_derive_raw_secret(wrapped_key, wrapped_key_size,
					   secret, secret_size);

	return err;
}

static const struct keyslot_mgmt_ll_ops cqhci_crypto_qti_ksm_ops = {
	.keyslot_program	= cqhci_crypto_qti_keyslot_program,
	.keyslot_evict		= cqhci_crypto_qti_keyslot_evict,
	.derive_raw_secret	= cqhci_crypto_qti_derive_raw_secret
};

enum blk_crypto_mode_num cqhci_blk_crypto_qti_mode_num_for_alg_dusize(
	enum cqhci_crypto_alg cqhci_crypto_alg,
	enum cqhci_crypto_key_size key_size)
{
	/*
	 * Currently the only mode that eMMC and blk-crypto both support.
	 */
	if (cqhci_crypto_alg == CQHCI_CRYPTO_ALG_AES_XTS &&
		key_size == CQHCI_CRYPTO_KEY_SIZE_256)
		return BLK_ENCRYPTION_MODE_AES_256_XTS;

	return BLK_ENCRYPTION_MODE_INVALID;
}

int cqhci_host_init_crypto_qti_spec(struct cqhci_host *host,
				    const struct keyslot_mgmt_ll_ops *ksm_ops)
{
	int cap_idx = 0;
	int err = 0;
	unsigned int features;
	unsigned int num_keyslots;
	unsigned int crypto_modes_supported[BLK_ENCRYPTION_MODE_MAX];
	enum blk_crypto_mode_num blk_mode_num;
	bool legacy_ice_v2 = cqhci_crypto_qti_is_legacy_ice_v2(host);
	u32 cqcap;

	/* Default to disabling crypto */
	host->caps &= ~(CQHCI_CAP_CRYPTO_SUPPORT | CQHCI_TASK_DESC_SZ_128);
	host->ksm = NULL;
	host->crypto_cap_array = NULL;
	host->crypto_capabilities.reg_val = 0;
	host->crypto_cfg_register = 0;
	host->crypto_ice2 = legacy_ice_v2;

	cqcap = cqhci_readl(host, CQHCI_CAP);
	if (!(cqcap & CQHCI_CAP_CS) && !legacy_ice_v2) {
		pr_debug("%s no crypto capability\n", __func__);
		err = -ENODEV;
		goto out;
	}

	memset(crypto_modes_supported, 0, sizeof(crypto_modes_supported));
	if (legacy_ice_v2) {
		/*
		 * CQHCI_CCAP/CRYPTOCAP overlap the legacy vendor register window,
		 * and the working 4.9 driver never interprets them.  The ICE2/TZ
		 * contract itself defines 30 usable AES-XTS slots (2 through 31),
		 * so describe only those known capabilities.
		 */
		host->crypto_capabilities.num_crypto_cap = 1;
		host->crypto_capabilities.config_count =
			QTI_LEGACY_ICE_V2_NUM_KEYSLOTS - 1;
		host->crypto_cap_array =
			devm_kcalloc(mmc_dev(host->mmc), 1,
					sizeof(host->crypto_cap_array[0]),
					GFP_KERNEL);
		if (!host->crypto_cap_array) {
			err = -ENOMEM;
			goto out;
		}
		host->crypto_cap_array[0].algorithm_id =
			CQHCI_CRYPTO_ALG_AES_XTS;
		host->crypto_cap_array[0].key_size =
			CQHCI_CRYPTO_KEY_SIZE_256;
		host->crypto_cap_array[0].sdus_mask =
			get_data_unit_size_mask(QTI_LEGACY_ICE_V2_KSM_DUS);
		crypto_modes_supported[BLK_ENCRYPTION_MODE_AES_256_XTS] =
			QTI_LEGACY_ICE_V2_KSM_DUS;
	} else {
		/* A zero standard CCAP means crypto initialization failed. */
		host->crypto_capabilities.reg_val = cqhci_readl(host,
								 CQHCI_CCAP);
		if (!host->crypto_capabilities.reg_val ||
		    !host->crypto_capabilities.num_crypto_cap) {
			err = -ENODEV;
			goto out;
		}

		host->crypto_cfg_register =
			(u32)host->crypto_capabilities.config_array_ptr * 0x100;
		host->crypto_cap_array =
			devm_kcalloc(mmc_dev(host->mmc),
					host->crypto_capabilities.num_crypto_cap,
					sizeof(host->crypto_cap_array[0]),
					GFP_KERNEL);
		if (!host->crypto_cap_array) {
			err = -ENOMEM;
			goto out;
		}

		for (cap_idx = 0;
		     cap_idx < host->crypto_capabilities.num_crypto_cap;
		     cap_idx++) {
			host->crypto_cap_array[cap_idx].reg_val =
				cpu_to_le32(cqhci_readl(host,
						 CQHCI_CRYPTOCAP +
						 cap_idx * sizeof(__le32)));
			blk_mode_num =
				cqhci_blk_crypto_qti_mode_num_for_alg_dusize(
					host->crypto_cap_array[cap_idx].algorithm_id,
					host->crypto_cap_array[cap_idx].key_size);
			if (blk_mode_num == BLK_ENCRYPTION_MODE_INVALID)
				continue;
			crypto_modes_supported[blk_mode_num] |=
				host->crypto_cap_array[cap_idx].sdus_mask * 512;
		}
	}

	features = BLK_CRYPTO_FEATURE_STANDARD_KEYS;
	if (!legacy_ice_v2)
		features |= BLK_CRYPTO_FEATURE_WRAPPED_KEYS;
	num_keyslots = legacy_ice_v2 ? QTI_LEGACY_ICE_V2_NUM_KEYSLOTS :
					 cqhci_num_keyslots(host);
	host->ksm = keyslot_manager_create(host->mmc->parent,
					   num_keyslots, ksm_ops, features,
					   crypto_modes_supported, host);

	if (!host->ksm) {
		err = -ENOMEM;
		goto out;
	}
	keyslot_manager_set_max_dun_bytes(host->ksm,
		legacy_ice_v2 ? sizeof(u64) : sizeof(u32));

	/*
	 * In case host controller supports cryptographic operations
	 * then, it uses 128bit task descriptor. Upper 64 bits of task
	 * descriptor would be used to pass crypto specific informaton.
	 */
	if (!legacy_ice_v2)
		host->caps |= CQHCI_TASK_DESC_SZ_128;

	return 0;

out:
	if (host->ksm) {
		keyslot_manager_destroy(host->ksm);
		host->ksm = NULL;
	}
	if (host->crypto_cap_array) {
		devm_kfree(mmc_dev(host->mmc), host->crypto_cap_array);
		host->crypto_cap_array = NULL;
	}
	/* Indicate that init failed by setting crypto_capabilities to 0 */
	host->crypto_capabilities.reg_val = 0;
	host->crypto_cfg_register = 0;
	host->caps &= ~(CQHCI_CAP_CRYPTO_SUPPORT | CQHCI_TASK_DESC_SZ_128);
	host->crypto_ice2 = false;
	return err;
}

int cqhci_crypto_qti_init_crypto(struct cqhci_host *host,
				const struct keyslot_mgmt_ll_ops *ksm_ops)
{
	int err = 0;
	u32 ice_version;
	u32 ice_major;
	bool legacy_ice_v2;
	struct sdhci_host *sdhci = mmc_priv(host->mmc);
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(sdhci);
	struct sdhci_msm_host *msm_host = pltfm_host->priv;
	struct resource *cqhci_ice_memres = NULL;

	cqhci_ice_memres = platform_get_resource_byname(msm_host->pdev,
							IORESOURCE_MEM,
							"cqhci_ice");
	if (!cqhci_ice_memres) {
		pr_debug("%s ICE not supported\n", __func__);
		host->icemmio = NULL;
		host->caps &= ~CQHCI_CAP_CRYPTO_SUPPORT;
		return err;
	}

	host->icemmio = devm_ioremap(&msm_host->pdev->dev,
				     cqhci_ice_memres->start,
				     resource_size(cqhci_ice_memres));
	if (!host->icemmio) {
		pr_err("%s failed to remap ice regs\n", __func__);
		return -ENOMEM;
	}

	/* Identify the ICE generation before interpreting CQHCI capabilities. */
	ice_version = readl_relaxed(host->icemmio + QTI_ICE_REG_VERSION);
	ice_major = QTI_ICE_VERSION_MAJOR(ice_version);
	legacy_ice_v2 = cqhci_crypto_qti_is_legacy_ice_v2(host);
	dev_info(&msm_host->pdev->dev, "ICE revision %u.%u.%u%s\n",
		 ice_major, QTI_ICE_VERSION_MINOR(ice_version),
		 QTI_ICE_VERSION_STEP(ice_version),
		 legacy_ice_v2 ? " (legacy CQHCI mode)" : "");

	if ((legacy_ice_v2 && ice_major != 2) ||
	    (!legacy_ice_v2 && ice_major == 2)) {
		dev_err(&msm_host->pdev->dev,
			"ICE2 and %s must agree (revision 0x%08x)\n",
			QTI_LEGACY_ICE_V2_PROP, ice_version);
		err = -ENODEV;
		goto out_disable_crypto;
	}

	/* Do not publish a KSM until the generation-specific ICE init works. */
	err = crypto_qti_init_crypto(&msm_host->pdev->dev,
			host->icemmio, (void **)&host->crypto_vops->priv);
	if (err) {
		pr_err("%s: Error initiating crypto, err %d\n",
					__func__, err);
		goto out_disable_crypto;
	}

	err = cqhci_host_init_crypto_qti_spec(host,
					     &cqhci_crypto_qti_ksm_ops);
	if (err) {
		pr_err("%s: Error initiating crypto capabilities, err %d\n",
					__func__, err);
		goto out_disable_crypto;
	}

	atomic_set(&keycache, 0);
	return 0;

out_disable_crypto:
	if (host->ksm) {
		keyslot_manager_destroy(host->ksm);
		host->ksm = NULL;
	}
	host->crypto_capabilities.reg_val = 0;
	host->caps &= ~(CQHCI_CAP_CRYPTO_SUPPORT | CQHCI_TASK_DESC_SZ_128);
	return err;
}


int cqhci_crypto_qti_prep_desc(struct cqhci_host *host, struct mmc_request *mrq,
	u64 *ice_ctx)
{
	struct bio_crypt_ctx *bc;
	struct mmc_queue_req *mqrq = container_of(mrq, struct mmc_queue_req,
						  brq.mrq);
	struct request *req = mmc_queue_req_to_req(mqrq);
	int ret = 0;
	int val = 0;
	unsigned int hw_keyslot;
#if IS_ENABLED(CONFIG_CRYPTO_DEV_QCOM_ICE)
	struct ice_data_setting setting = { 0 };
	bool bypass = true;
	short key_index = 0;
#endif

	*ice_ctx = 0;

	if (!req || !req->bio)
		return ret;

	if (!bio_crypt_should_process(req)) {
#if IS_ENABLED(CONFIG_CRYPTO_DEV_QCOM_ICE)
		ret = qcom_ice_config_start(req, &setting);
		if (!ret) {
			key_index = setting.crypto_data.key_index;
			bypass = (rq_data_dir(req) == WRITE) ?
				setting.encr_bypass : setting.decr_bypass;
			if (host->crypto_ice2)
				ret = cqhci_crypto_qti_ice2_config(host, mrq,
							req->__sector, bypass,
							key_index,
							QTI_ICE2_DU_512_B);
			else
				*ice_ctx = DATA_UNIT_NUM(req->__sector) |
					CRYPTO_CONFIG_INDEX(key_index) |
					CRYPTO_ENABLE(!bypass);
		} else {
			pr_err("%s crypto config failed err = %d\n", __func__,
					ret);
		}
#endif
		return ret;
	}
	if (WARN_ON(!cqhci_is_crypto_enabled(host))) {
		/*
		 * Upper layer asked us to do inline encryption
		 * but that isn't enabled, so we fail this request.
		 */
		return -EINVAL;
	}

	bc = req->bio->bi_crypt_context;

	if (!host->ksm ||
	    !cqhci_keyslot_valid(host, bc->bc_keyslot))
		return -EINVAL;
	hw_keyslot = cqhci_crypto_qti_hw_keyslot(host, bc->bc_keyslot);

	if (!(atomic_read(&keycache) & BIT(bc->bc_keyslot))) {
		if (host->crypto_ice2) {
			pr_err("%s: ICE2 logical keyslot %d was not programmed\n",
			       __func__, bc->bc_keyslot);
			return -ENOKEY;
		}

		if (bc->is_ext4)
			cmdq_use_default_du_size = true;
		else
			cmdq_use_default_du_size = false;

		ret = cqhci_crypto_qti_keyslot_program(host->ksm, bc->bc_key,
						       bc->bc_keyslot);
		if (ret) {
			pr_err("%s keyslot program failed %d\n", __func__, ret);
			return ret;
		}
		val = atomic_read(&keycache) | BIT(bc->bc_keyslot);
		atomic_set(&keycache, val);
	}

	if (host->crypto_ice2) {
		ret = cqhci_crypto_qti_ice2_config(host, mrq, req->__sector,
						   false, hw_keyslot,
						   QTI_ICE2_DU_512_B);
		return ret;
	}

	if (ice_ctx) {
		if (bc->is_ext4)
			*ice_ctx = DATA_UNIT_NUM(req->__sector);
		else
			*ice_ctx = DATA_UNIT_NUM(bc->bc_dun[0]);

		*ice_ctx = *ice_ctx | CRYPTO_CONFIG_INDEX(hw_keyslot) |
			    CRYPTO_ENABLE(true);
	}
	return 0;
}


int cqhci_crypto_qti_debug(struct cqhci_host *host)
{
	if (!cqhci_host_is_crypto_supported(host) ||
	    !host->crypto_vops->priv)
		return 0;

	return crypto_qti_debug(host->crypto_vops->priv);
}

void cqhci_crypto_qti_set_vops(struct cqhci_host *host)
{
	cqhci_crypto_set_vops(host, &cqhci_crypto_qti_variant_ops);
}

int cqhci_crypto_qti_resume(struct cqhci_host *host)
{
	if (!cqhci_host_is_crypto_supported(host) ||
	    !host->ksm || !host->crypto_vops->priv)
		return 0;

	return crypto_qti_resume(host->crypto_vops->priv);
}

int cqhci_crypto_qti_recovery_finish(struct cqhci_host *host)
{
	int ret;

	if (!cqhci_host_is_crypto_supported(host) || !host->ksm)
		return 0;

	if (host->crypto_ice2) {
		ret = crypto_qti_resume(host->crypto_vops->priv);
		if (ret)
			return ret;
	}

	keyslot_manager_reprogram_all_keys(host->ksm);
	return 0;
}

static void cqhci_crypto_qti_setup_rq_keyslot_manager(
					struct cqhci_host *host,
					struct request_queue *q)
{
	if (!q || !host->ksm || !cqhci_host_is_crypto_supported(host))
		return;

	q->ksm = host->ksm;
}

static void cqhci_crypto_qti_destroy_rq_keyslot_manager(
					struct cqhci_host *host,
					struct request_queue *q)
{
	if (!host->ksm)
		return;

	if (q && q->ksm == host->ksm)
		q->ksm = NULL;
	keyslot_manager_destroy(host->ksm);
	host->ksm = NULL;
}
