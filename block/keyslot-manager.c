// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/keyslot-manager.h>
#include <linux/atomic.h>

#define KSM_MAX_SLOTS 65536

struct keyslot_manager *keyslot_manager_create(unsigned int num_slots,
				const struct keyslot_mgmt_ll_ops *ksm_ll_ops,
				void *ll_priv_data)
{
	struct keyslot_manager *ksm;

	if (num_slots > KSM_MAX_SLOTS || num_slots == 0)
		return NULL;

	/* Check that all ops are specified */
	if (ksm_ll_ops->keyslot_program == NULL ||
		ksm_ll_ops->crypto_alg_find == NULL ||
		ksm_ll_ops->keyslot_find == NULL ||
		ksm_ll_ops->keyslot_evict == NULL) {
		return NULL;
	}

	ksm = kzalloc(sizeof(struct keyslot_manager) +
			      sizeof(atomic_t) * num_slots +
			      sizeof(u64) * num_slots, GFP_KERNEL);
	if (!ksm)
		return NULL;

	ksm->num_slots = num_slots;
	atomic_set(&ksm->num_idle_slots, num_slots);
	ksm->ksm_ll_ops = *ksm_ll_ops;
	ksm->ll_priv_data = ll_priv_data;

	mutex_init(&ksm->lock);
	init_waitqueue_head(&ksm->wait_queue);

	ksm->last_used_seq_nums = (u64 *) (((char *)ksm) + sizeof(*ksm) +
					  sizeof(atomic_t) * num_slots);

	return ksm;
}
EXPORT_SYMBOL(keyslot_manager_create);

int keyslot_manager_get_slot_for_key(struct keyslot_manager *ksm,
				     const u8 *key,
				     enum blk_crypt_mode_index crypt_mode,
				     unsigned int dataunit_size)
{
	int crypto_alg_id;
	int slot;
	int err;
	int c;
	int min_idx;
	u64 min_val;

	if (!ksm)
		return -EINVAL;

	crypto_alg_id = ksm->ksm_ll_ops.crypto_alg_find(ksm->ll_priv_data,
							crypt_mode,
							dataunit_size);
	if (crypto_alg_id < 0)
		return crypto_alg_id;

	mutex_lock(&ksm->lock);
	slot = ksm->ksm_ll_ops.keyslot_find(ksm->ll_priv_data, key,
					    dataunit_size,
					    (unsigned int)crypto_alg_id);

	if (slot < 0 && slot != -ENOKEY) {
		mutex_unlock(&ksm->lock);
		return slot;
	}

	if (WARN_ON(slot >= (int)ksm->num_slots)) {
		mutex_unlock(&ksm->lock);
		return -EINVAL;
	}

	/* Try to use the returned slot */
	if (slot != -ENOKEY) {
		/**
		 * NOTE: We may fail to get a slot if the number of refs
		 * overflows UINT_MAX. I don't think we care enough about
		 * that possibility to make the refcounts u64, considering
		 * the only way for that to happen is for at least UINT_MAX
		 * requests to be in flight at the same time.
		 */
		if ((unsigned int)atomic_read(&ksm->slot_refs[slot]) ==
		    UINT_MAX) {
			mutex_unlock(&ksm->lock);
			return -EBUSY;
		}

		if (atomic_fetch_inc(&ksm->slot_refs[slot]) == 0)
			atomic_dec(&ksm->num_idle_slots);

		ksm->seq_num++;
		ksm->last_used_seq_nums[slot] = ksm->seq_num;

		mutex_unlock(&ksm->lock);
		return slot;
	}

	/*
	 * If we're here, that means there wasn't a slot that
	 * was already programmed with the key
	 */

	/* Wait till there is a free slot available */
	while (atomic_read(&ksm->num_idle_slots) == 0) {
		mutex_unlock(&ksm->lock);
		wait_event(ksm->wait_queue,
			   (atomic_read(&ksm->num_idle_slots) > 0));
		mutex_lock(&ksm->lock);
	}

	/* Todo: fix linear scan? */
	min_idx = -1;
	min_val = 0;
	for (c = 0; c < ksm->num_slots; c++) {
		if (atomic_read(&ksm->slot_refs[c]) != 0)
			continue;

		if (min_idx == -1 || ksm->last_used_seq_nums[c] < min_val) {
			min_idx = c;
			min_val = ksm->last_used_seq_nums[c];
		}
	}

	/* This should never happen */
	if (WARN_ON(min_idx == -1)) {
		mutex_unlock(&ksm->lock);
		return -EBUSY;
	}

	atomic_dec(&ksm->num_idle_slots);
	atomic_inc(&ksm->slot_refs[min_idx]);
	err = ksm->ksm_ll_ops.keyslot_program(ksm->ll_priv_data, key,
					      dataunit_size,
					      crypto_alg_id,
					      min_idx);

	if (err) {
		atomic_dec(&ksm->slot_refs[min_idx]);
		atomic_inc(&ksm->num_idle_slots);
		wake_up(&ksm->wait_queue);
		mutex_unlock(&ksm->lock);
		return err;
	}

	ksm->seq_num++;
	ksm->last_used_seq_nums[min_idx] = ksm->seq_num;

	mutex_unlock(&ksm->lock);
	return min_idx;
}
EXPORT_SYMBOL(keyslot_manager_get_slot_for_key);

bool keyslot_manager_get_slot(struct keyslot_manager *ksm,
			     unsigned int slot)
{
	if (WARN_ON(slot >= ksm->num_slots))
		return false;

	return atomic_inc_not_zero(&ksm->slot_refs[slot]);
}
EXPORT_SYMBOL(keyslot_manager_get_slot);

int keyslot_manager_put_slot(struct keyslot_manager *ksm,
				 unsigned int slot)
{
	if (WARN_ON(slot >= ksm->num_slots))
		return -EINVAL;

	if (atomic_dec_and_test(&ksm->slot_refs[slot])) {
		atomic_inc(&ksm->num_idle_slots);
		wake_up(&ksm->wait_queue);
	}

	return 0;
}
EXPORT_SYMBOL(keyslot_manager_put_slot);

int keyslot_manager_evict_key(struct keyslot_manager *ksm,
			    const u8 *key,
			    enum blk_crypt_mode_index crypt_mode,
			    unsigned int dataunit_size)
{
	int slot;
	int crypto_alg_id;
	int err = 0;

	crypto_alg_id = ksm->ksm_ll_ops.crypto_alg_find(ksm->ll_priv_data,
							crypt_mode,
							dataunit_size);
	if (crypto_alg_id < 0)
		return -EINVAL;

	mutex_lock(&ksm->lock);
	slot = ksm->ksm_ll_ops.keyslot_find(ksm->ll_priv_data, key,
					    dataunit_size,
					    (unsigned int)crypto_alg_id);

	if (slot < 0) {
		mutex_unlock(&ksm->lock);
		return slot;
	}

	if (atomic_read(&ksm->slot_refs[slot]) == 0)
		err = ksm->ksm_ll_ops.keyslot_evict(ksm->ll_priv_data, slot,
						    key, dataunit_size,
						    crypto_alg_id);

	mutex_unlock(&ksm->lock);
	return err;
}
EXPORT_SYMBOL(keyslot_manager_evict_key);

void keyslot_manager_destroy(struct keyslot_manager *ksm)
{
	kzfree(ksm);
}
EXPORT_SYMBOL(keyslot_manager_destroy);
