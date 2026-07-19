/*
 * drivers/staging/android/ion/compat_ion.c
 *
 * Copyright (C) 2013 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "ion.h"
#include "compat_ion.h"
#include "ion_legacy.h"

/* See drivers/staging/android/uapi/ion.h for the definition of these structs */
struct compat_ion_old_allocation_data {
	compat_size_t len;
	compat_size_t align;
	compat_uint_t heap_id_mask;
	compat_uint_t flags;
	compat_int_t handle;
};

struct compat_ion_handle_data {
	compat_int_t handle;
};

struct compat_ion_custom_data {
	compat_uint_t cmd;
	compat_ulong_t arg;
};

struct compat_ion_flush_data {
	compat_int_t handle;
	compat_int_t fd;
	compat_uptr_t vaddr;
	compat_uint_t offset;
	compat_uint_t length;
};

#define COMPAT_ION_IOC_ALLOC	_IOWR(ION_IOC_MAGIC, 0, \
				      struct compat_ion_old_allocation_data)
#define COMPAT_ION_IOC_FREE	_IOWR(ION_IOC_MAGIC, 1, \
				      struct compat_ion_handle_data)
#define COMPAT_ION_IOC_CUSTOM	_IOWR(ION_IOC_MAGIC, 6, \
				      struct compat_ion_custom_data)
#define COMPAT_ION_IOC_CLEAN_CACHES	_IOWR(ION_IOC_MSM_MAGIC, 0, \
					      struct compat_ion_flush_data)
#define COMPAT_ION_IOC_INV_CACHES	_IOWR(ION_IOC_MSM_MAGIC, 1, \
					      struct compat_ion_flush_data)
#define COMPAT_ION_IOC_CLEAN_INV_CACHES _IOWR(ION_IOC_MSM_MAGIC, 2, \
					      struct compat_ion_flush_data)

static int compat_get_ion_allocation_data(
			struct compat_ion_old_allocation_data __user *data32,
			struct ion_old_allocation_data __user *data)
{
	compat_size_t s;
	compat_uint_t u;
	compat_int_t i;
	int err;

	err = get_user(s, &data32->len);
	err |= put_user(s, &data->len);
	err |= get_user(s, &data32->align);
	err |= put_user(s, &data->align);
	err |= get_user(u, &data32->heap_id_mask);
	err |= put_user(u, &data->heap_id_mask);
	err |= get_user(u, &data32->flags);
	err |= put_user(u, &data->flags);
	err |= get_user(i, &data32->handle);
	err |= put_user(i, &data->handle);

	return err;
}

static int compat_get_ion_handle_data(
			struct compat_ion_handle_data __user *data32,
			struct ion_handle_data __user *data)
{
	compat_int_t i;
	int err;

	err = get_user(i, &data32->handle);
	err |= put_user(i, &data->handle);

	return err;
}

static int compat_put_ion_allocation_data(
			struct compat_ion_old_allocation_data __user *data32,
			struct ion_old_allocation_data __user *data)
{
	compat_size_t s;
	compat_uint_t u;
	compat_int_t i;
	int err;

	err = get_user(s, &data->len);
	err |= put_user(s, &data32->len);
	err |= get_user(s, &data->align);
	err |= put_user(s, &data32->align);
	err |= get_user(u, &data->heap_id_mask);
	err |= put_user(u, &data32->heap_id_mask);
	err |= get_user(u, &data->flags);
	err |= put_user(u, &data32->flags);
	err |= get_user(i, &data->handle);
	err |= put_user(i, &data32->handle);

	return err;
}

static unsigned int compat_ion_cache_cmd(unsigned int cmd)
{
	switch (cmd) {
	case COMPAT_ION_IOC_CLEAN_CACHES:
		return ION_IOC_CLEAN_CACHES;
	case COMPAT_ION_IOC_INV_CACHES:
		return ION_IOC_INV_CACHES;
	case COMPAT_ION_IOC_CLEAN_INV_CACHES:
		return ION_IOC_CLEAN_INV_CACHES;
	default:
		return 0;
	}
}

static int compat_get_ion_flush_data(
			struct compat_ion_flush_data __user *data32,
			struct ion_flush_data __user *data)
{
	compat_int_t handle;
	compat_int_t fd;
	compat_uptr_t vaddr;
	compat_uint_t offset;
	compat_uint_t length;
	int err;

	err = get_user(handle, &data32->handle);
	err |= put_user(handle, &data->handle);
	err |= get_user(fd, &data32->fd);
	err |= put_user(fd, &data->fd);
	err |= get_user(vaddr, &data32->vaddr);
	err |= put_user(NULL, &data->vaddr);
	err |= put_user(vaddr, (compat_uptr_t __user *)&data->vaddr);
	err |= get_user(offset, &data32->offset);
	err |= put_user(offset, &data->offset);
	err |= get_user(length, &data32->length);
	err |= put_user(length, &data->length);

	return err;
}

static long compat_ion_custom_ioctl(struct file *filp, unsigned long arg)
{
	struct compat_ion_custom_data __user *custom32 = compat_ptr(arg);
	struct compat_ion_flush_data __user *flush32;
	struct ion_custom_data __user *custom;
	struct ion_flush_data __user *flush;
	compat_ulong_t flush_arg;
	compat_uint_t cmd32;
	unsigned int cmd;
	int err;

	err = get_user(cmd32, &custom32->cmd);
	err |= get_user(flush_arg, &custom32->arg);
	if (err)
		return err;

	cmd = compat_ion_cache_cmd(cmd32);
	if (!cmd)
		return -ENOIOCTLCMD;

	custom = compat_alloc_user_space(sizeof(*custom) + sizeof(*flush));
	if (!custom)
		return -EFAULT;
	flush = (struct ion_flush_data __user *)(custom + 1);
	flush32 = compat_ptr(flush_arg);

	err = compat_get_ion_flush_data(flush32, flush);
	err |= put_user(cmd, &custom->cmd);
	err |= put_user((unsigned long)flush, &custom->arg);
	if (err)
		return err;

	return filp->f_op->unlocked_ioctl(filp, ION_IOC_CUSTOM,
						(unsigned long)custom);
}

long compat_ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret;

	if (!filp->f_op->unlocked_ioctl)
		return -ENOTTY;

	switch (cmd) {
	case COMPAT_ION_IOC_ALLOC:
	{
		struct compat_ion_old_allocation_data __user *data32;
		struct ion_old_allocation_data __user *data;
		int err;

		data32 = compat_ptr(arg);
		data = compat_alloc_user_space(sizeof(*data));
		if (!data)
			return -EFAULT;

		err = compat_get_ion_allocation_data(data32, data);
		if (err)
			return err;
		ret = filp->f_op->unlocked_ioctl(filp, ION_OLD_IOC_ALLOC,
							(unsigned long)data);
		err = compat_put_ion_allocation_data(data32, data);
		return ret ? ret : err;
	}
	case COMPAT_ION_IOC_FREE:
	{
		struct compat_ion_handle_data __user *data32;
		struct ion_handle_data __user *data;
		int err;

		data32 = compat_ptr(arg);
		data = compat_alloc_user_space(sizeof(*data));
		if (!data)
			return -EFAULT;

		err = compat_get_ion_handle_data(data32, data);
		if (err)
			return err;

		return filp->f_op->unlocked_ioctl(filp, ION_IOC_FREE,
							(unsigned long)data);
	}
	case COMPAT_ION_IOC_CUSTOM:
		return compat_ion_custom_ioctl(filp, arg);
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
	case ION_IOC_ALLOC:
	case ION_IOC_HEAP_QUERY:
	case ION_IOC_PREFETCH:
	case ION_IOC_DRAIN:
		return filp->f_op->unlocked_ioctl(filp, cmd,
						(unsigned long)compat_ptr(arg));
	default:
		return -ENOIOCTLCMD;
	}
}
