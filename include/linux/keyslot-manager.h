// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_KEYSLOT_MANAGER_H
#define __LINUX_KEYSLOT_MANAGER_H

#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/types.h>
#include <linux/blk-crypto.h>

struct keyslot_mgmt_ll_ops {
	int (*keyslot_program)(void *ll_priv_data, const u8 *key,
				unsigned int dataunit_size,
				/* alg_type as returned by crypto alg find */
				unsigned int alg_type,
				unsigned int slot);
	/**
	 * Returns 0 on success, -errno otherwise.
	 * The key, dataunit_size and alg_type are also passed down
	 * so that for e.g. dm layers that have their own keyslot
	 * managers can evict keys from the devices that they map over.
	 */
	int (*keyslot_evict)(void *ll_priv_data, unsigned int slot,
			     const u8 *key, unsigned int dataunit_size,
			     unsigned int alg_type);
	int (*crypto_alg_find)(void *ll_priv_data,
			       enum blk_crypt_mode_index crypt_mode,
			       unsigned int dataunit_size);
	/**
	 * Returns the slot number that matches the key,
	 * or -ENOKEY if no match found, or negative on error
	 */
	int (*keyslot_find)(void *ll_priv_data, const u8 *key,
			    unsigned int dataunit_size,
			    unsigned int alg_type);
};

struct keyslot_manager {
	unsigned int num_slots;
	atomic_t num_idle_slots;
	struct keyslot_mgmt_ll_ops ksm_ll_ops;
	void *ll_priv_data;
	struct mutex lock;
	wait_queue_head_t wait_queue;
	u64 seq_num;
	u64 *last_used_seq_nums;
	atomic_t slot_refs[];
};

#ifdef CONFIG_BLK_KEYSLOT_MANAGER
extern struct keyslot_manager *keyslot_manager_create(unsigned int num_slots,
				const struct keyslot_mgmt_ll_ops *ksm_ops,
				void *ll_priv_data);

extern int
keyslot_manager_get_slot_for_key(struct keyslot_manager *ksm,
				 const u8 *key,
				 enum blk_crypt_mode_index crypt_mode,
				 unsigned int dataunit_size);

extern bool keyslot_manager_get_slot(struct keyslot_manager *ksm,
				    unsigned int slot);

extern int keyslot_manager_put_slot(struct keyslot_manager *ksm,
				    unsigned int slot);

extern int keyslot_manager_evict_key(struct keyslot_manager *ksm,
				     const u8 *key,
				     enum blk_crypt_mode_index crypt_mode,
				     unsigned int dataunit_size);

extern void keyslot_manager_destroy(struct keyslot_manager *ksm);

#else /* CONFIG_BLK_KEYSLOT_MANAGER */

static inline struct keyslot_manager *
keyslot_manager_create(unsigned int num_slots,
		       const struct keyslot_mgmt_ll_ops *ksm_ops,
		       void *ll_priv_data)
{
	return NULL;
}

static inline int
keyslot_manager_get_slot_for_key(struct keyslot_manager *ksm,
				 const u8 *key,
				 enum blk_crypt_mode_index crypt_mode,
				 unsigned int dataunit_size)
{
	return -EOPNOTSUPP;
}

static inline bool keyslot_manager_get_slot(struct keyslot_manager *ksm,
					   unsigned int slot)
{
	return -EOPNOTSUPP;
}

static inline int keyslot_manager_put_slot(struct keyslot_manager *ksm,
					   unsigned int slot)
{
	return -EOPNOTSUPP;
}

static inline int keyslot_manager_evict_key(struct keyslot_manager *ksm,
				     const u8 *key,
				     enum blk_crypt_mode_index crypt_mode,
				     unsigned int dataunit_size)
{
	return -EOPNOTSUPP;
}

static inline void keyslot_manager_destroy(struct keyslot_manager *ksm)
{ }

#endif /* CONFIG_BLK_KEYSLOT_MANAGER */

#endif /* __LINUX_KEYSLOT_MANAGER_H */
