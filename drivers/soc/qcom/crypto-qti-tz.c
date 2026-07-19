// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <asm/cacheflush.h>
#include <soc/qcom/scm.h>
#include <soc/qcom/qtee_shmbridge.h>
#include <crypto/ice.h>
#include <linux/crypto-qti-common.h>
#include "crypto-qti-ice-regs.h"
#include "crypto-qti-platform.h"
#include "crypto-qti-tz.h"

#define ICE_V2_MAJOR_VERSION	2
#define ICE_V2_XTS_KEY_SIZE	64
#define ICE_V2_KEY_HALF_SIZE	(ICE_V2_XTS_KEY_SIZE / 2)
#define ICE_V2_MIN_KEY_SLOT	2
#define ICE_V2_MAX_KEY_SLOT	31

unsigned int storage_type = SDCC_CE;

static bool crypto_qti_is_ice_v2(struct crypto_vops_qti_entry *ice_entry)
{
	return ((ice_entry->ice_hw_version & ICE_CORE_MAJOR_REV_MASK) >>
		ICE_CORE_MAJOR_REV) == ICE_V2_MAJOR_VERSION;
}

static int crypto_qti_program_key_v2(const u8 *key, unsigned int slot)
{
	struct qtee_shm shm_key = { 0 };
	struct qtee_shm shm_salt = { 0 };
	struct scm_desc desc = { 0 };
	u8 *key_buf;
	u8 *salt_buf;
	phys_addr_t key_paddr;
	phys_addr_t salt_paddr;
	bool use_shmbridge = qtee_shmbridge_is_enabled();
	int err, setup_err, disable_err;

	if (slot < ICE_V2_MIN_KEY_SLOT || slot > ICE_V2_MAX_KEY_SLOT) {
		pr_err("%s: invalid ICE2 keyslot %u\n", __func__, slot);
		return -EINVAL;
	}

	if (use_shmbridge) {
		err = qtee_shmbridge_allocate_shm(ICE_V2_KEY_HALF_SIZE,
						  &shm_key);
		if (err)
			return err;

		err = qtee_shmbridge_allocate_shm(ICE_V2_KEY_HALF_SIZE,
						  &shm_salt);
		if (err)
			goto out_free_key;
		key_buf = shm_key.vaddr;
		salt_buf = shm_salt.vaddr;
		key_paddr = shm_key.paddr;
		salt_paddr = shm_salt.paddr;
	} else {
		/* ICE2 firmware predating shmbridge expects normal physical pages. */
		key_buf = kzalloc(ICE_V2_KEY_HALF_SIZE, GFP_NOIO);
		if (!key_buf)
			return -ENOMEM;
		salt_buf = kzalloc(ICE_V2_KEY_HALF_SIZE, GFP_NOIO);
		if (!salt_buf) {
			kfree(key_buf);
			return -ENOMEM;
		}
		key_paddr = virt_to_phys(key_buf);
		salt_paddr = virt_to_phys(salt_buf);
	}

	memcpy(key_buf, key, ICE_V2_KEY_HALF_SIZE);
	memcpy(salt_buf, key + ICE_V2_KEY_HALF_SIZE,
	       ICE_V2_KEY_HALF_SIZE);
	dmac_flush_range(key_buf, key_buf + ICE_V2_KEY_HALF_SIZE);
	dmac_flush_range(salt_buf, salt_buf + ICE_V2_KEY_HALF_SIZE);

	desc.arginfo = TZ_ES_SET_ICE_KEY_V2_PARAM_ID;
	desc.args[0] = slot;
	desc.args[1] = key_paddr;
	desc.args[2] = ICE_V2_KEY_HALF_SIZE;
	desc.args[3] = salt_paddr;
	desc.args[4] = ICE_V2_KEY_HALF_SIZE;

	/*
	 * Working 4.9 raises the standalone SDCC ICE clocks and MAX bus vote
	 * around every key-management SCM call.  The CQHCI clock pair alone
	 * does not cover that control-plane contract on Rosy's ICE 2.1.
	 */
	setup_err = qcom_ice_setup_ice_hw("sdcc", true);
	if (setup_err) {
		pr_err("%s: ICE setup failed: %d\n", __func__, setup_err);
		err = setup_err;
		goto out_wipe_salt;
	}

	err = scm_call2_noretry(TZ_ES_SET_ICE_KEY_V2_ID, &desc);
	if (err)
		pr_err("%s: SCM call failed: 0x%x slot %u\n",
		       __func__, err, slot);
	disable_err = qcom_ice_setup_ice_hw("sdcc", false);
	if (disable_err)
		pr_err("%s: ICE teardown failed: %d\n", __func__, disable_err);

out_wipe_salt:
	memzero_explicit(salt_buf, ICE_V2_KEY_HALF_SIZE);
	if (use_shmbridge)
		qtee_shmbridge_free_shm(&shm_salt);
	else
		kfree(salt_buf);
out_free_key:
	if (use_shmbridge) {
		memzero_explicit(shm_key.vaddr, ICE_V2_KEY_HALF_SIZE);
		qtee_shmbridge_free_shm(&shm_key);
	} else {
		memzero_explicit(key_buf, ICE_V2_KEY_HALF_SIZE);
		kfree(key_buf);
	}
	return err;
}

int crypto_qti_program_key(struct crypto_vops_qti_entry *ice_entry,
			   const struct blk_crypto_key *key,
			   unsigned int slot, unsigned int data_unit_mask,
			   int capid)
{
	int err = 0;
	uint32_t smc_id = 0;
	char *tzbuf = NULL;
	struct qtee_shm shm = { 0 };
	struct scm_desc desc = {0};
	int i;
	bool ice_v2 = crypto_qti_is_ice_v2(ice_entry);
	union {
		u8 bytes[BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE];
		u32 words[BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE / sizeof(u32)];
	} key_new = { 0 };

	if (!key->size || key->size > sizeof(key_new.bytes) ||
	    key->size % sizeof(u32))
		return -EINVAL;

	if (ice_v2 &&
	    (key->is_hw_wrapped || key->size != ICE_V2_XTS_KEY_SIZE))
		return -EINVAL;

	memcpy(key_new.bytes, key->raw, key->size);
	/*
	 * Match the working 4.9 PFK ICE2 path: legacy private-mode key
	 * material is passed to SET_KEY as raw 32-byte key + raw 32-byte salt.
	 * Do not apply the standard CE-type word swap on this ICE2 ABI.
	 */
	if (!key->is_hw_wrapped && !ice_v2) {
		for (i = 0; i < key->size / sizeof(u32); i++)
			__cpu_to_be32s(&key_new.words[i]);
	}

	if (ice_v2) {
		err = crypto_qti_program_key_v2(key_new.bytes, slot);
		memzero_explicit(&key_new, sizeof(key_new));
		return err;
	}

	err = qtee_shmbridge_allocate_shm(key->size, &shm);
	if (err) {
		memzero_explicit(&key_new, sizeof(key_new));
		return err;
	}

	tzbuf = shm.vaddr;

	memcpy(tzbuf, key_new.bytes, key->size);
	dmac_flush_range(tzbuf, tzbuf + key->size);

	smc_id = TZ_ES_CONFIG_SET_ICE_KEY_CE_TYPE_ID;
	desc.arginfo = TZ_ES_CONFIG_SET_ICE_KEY_CE_TYPE_PARAM_ID;
	desc.args[0] = slot;
	desc.args[1] = shm.paddr;
	desc.args[2] = key->size;
	desc.args[3] = ICE_CIPHER_MODE_XTS_256;
	desc.args[4] = data_unit_mask;
	desc.args[5] = storage_type;


	err = scm_call2_noretry(smc_id, &desc);
	if (err)
		pr_err("%s:SCM call Error: 0x%x slot %d\n",
				__func__, err, slot);

	memzero_explicit(tzbuf, key->size);
	qtee_shmbridge_free_shm(&shm);
	memzero_explicit(&key_new, sizeof(key_new));

	return err;
}

int crypto_qti_invalidate_key(
		struct crypto_vops_qti_entry *ice_entry, unsigned int slot)
{
	int err = 0;
	int setup_err = 0;
	int disable_err = 0;
	uint32_t smc_id = 0;
	struct scm_desc desc = {0};

	if (crypto_qti_is_ice_v2(ice_entry)) {
		if (slot < ICE_V2_MIN_KEY_SLOT || slot > ICE_V2_MAX_KEY_SLOT) {
			pr_err("%s: invalid ICE2 keyslot %u\n", __func__, slot);
			return -EINVAL;
		}

		smc_id = TZ_ES_INVALIDATE_ICE_KEY_V2_ID;
		desc.arginfo = TZ_ES_INVALIDATE_ICE_KEY_V2_PARAM_ID;
		desc.args[0] = slot;
	} else {
		smc_id = TZ_ES_INVALIDATE_ICE_KEY_CE_TYPE_ID;
		desc.arginfo = TZ_ES_INVALIDATE_ICE_KEY_CE_TYPE_PARAM_ID;
		desc.args[0] = slot;
		desc.args[1] = storage_type;
	}

	if (crypto_qti_is_ice_v2(ice_entry)) {
		setup_err = qcom_ice_setup_ice_hw("sdcc", true);
		if (setup_err)
			return setup_err;
	}

	err = scm_call2_noretry(smc_id, &desc);
	if (crypto_qti_is_ice_v2(ice_entry)) {
		disable_err = qcom_ice_setup_ice_hw("sdcc", false);
		if (!err && disable_err)
			err = disable_err;
	}
	if (err)
		pr_err("%s:SCM call Error: 0x%x\n", __func__, err);
	return err;
}

int crypto_qti_tz_raw_secret(const u8 *wrapped_key,
			     unsigned int wrapped_key_size, u8 *secret,
			     unsigned int secret_size)
{
	int err = 0;
	struct qtee_shm shm_key, shm_secret;
	uint32_t smc_id = 0;

	struct scm_desc desc = {0};
	char *tzbuf_key;

	err = qtee_shmbridge_allocate_shm(wrapped_key_size, &shm_key);
	if (err)
		return -ENOMEM;

	err = qtee_shmbridge_allocate_shm(secret_size, &shm_secret);
	if (err)
		return -ENOMEM;

	tzbuf_key = shm_key.vaddr;
	memcpy(tzbuf_key, wrapped_key, wrapped_key_size);
	dmac_flush_range(tzbuf_key, tzbuf_key + wrapped_key_size);

	smc_id = TZ_ES_RETRIEVE_RAW_SECRET_CE_TYPE_ID;
	desc.arginfo = TZ_ES_RETRIEVE_RAW_SECRET_CE_TYPE_PARAM_ID;
	desc.args[0] = shm_key.paddr;
	desc.args[1] = wrapped_key_size;
	desc.args[2] = shm_secret.paddr;
	desc.args[3] = secret_size;

	memset(shm_secret.vaddr, 0, secret_size);
	dmac_flush_range(shm_secret.vaddr, shm_secret.vaddr + secret_size);

	err = scm_call2(smc_id, &desc);
	if (err) {
		pr_err("%s failed to retrieve raw secret\n", __func__, err);
		return err;
	}

	dmac_inv_range(shm_secret.vaddr, shm_secret.vaddr + secret_size);
	memcpy(secret, shm_secret.vaddr, secret_size);

	qtee_shmbridge_free_shm(&shm_key);
	qtee_shmbridge_free_shm(&shm_secret);

	return err;
}

static int crypto_qti_storage_type(unsigned int *s_type)
{
	char boot[20] = {'\0'};
	char *match = (char *)strnstr(saved_command_line,
				"androidboot.bootdevice=",
				strlen(saved_command_line));
	if (match) {
		memcpy(boot, (match + strlen("androidboot.bootdevice=")),
			sizeof(boot) - 1);
		if (strnstr(boot, "ufs", strlen(boot)))
			*s_type = UFS_CE;

		return 0;
	}
	return -EINVAL;
}

static int __init crypto_qti_init(void)
{
	return crypto_qti_storage_type(&storage_type);
}

module_init(crypto_qti_init);
