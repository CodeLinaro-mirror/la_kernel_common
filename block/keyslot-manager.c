#include <linux/types.h>
#include <linux/slab.h>
#include <linux/keyslot-manager.h>
#include <linux/atomic.h>

#define KSM_MAX_SLOTS 65536

struct keyslot_manager *keyslot_manager_create(unsigned int num_slots,
					struct keyslot_mgmt_ll_ops *ksm_ll_ops,
					void *ll_priv_data) {
	struct keyslot_manager *ksm;
	int c;

	if (num_slots > KSM_MAX_SLOTS || num_slots == 0) {
		return NULL;
	}

	/* Check that all ops are specified */
	if (ksm_ll_ops->keyslot_program == NULL ||
		ksm_ll_ops->keyslot_release == NULL ||
		ksm_ll_ops->crypto_alg_find == NULL ||
		ksm_ll_ops->keyslot_find == NULL ||
		ksm_ll_ops->keyslot_evict == NULL) {
		return NULL;
	}

	ksm = kzalloc(sizeof(struct keyslot_manager) +
			      sizeof(atomic_t) * num_slots, GFP_KERNEL);
	if (!ksm) {
		return NULL;
	}
	ksm->num_slots = num_slots;
	atomic_set(&ksm->num_free_slots, num_slots);
	ksm->slot_refs = (atomic_t*)((char*)ksm + sizeof(struct keyslot_manager));
	ksm->ksm_ll_ops = *ksm_ll_ops;
	ksm->ll_priv_data = ll_priv_data;

	mutex_init(&ksm->lock);
	init_waitqueue_head(&ksm->wait_queue);

	for (c = 0; c < num_slots; c++) {
		atomic_set(&(ksm->slot_refs[c]), 0);
	}

	return ksm;
}
EXPORT_SYMBOL(keyslot_manager_create);

int keyslot_manager_get_slot(struct keyslot_manager *ksm,
			    u8 *key, size_t key_size_bytes,
			    enum keyslot_manager_algs alg,
			    unsigned int dataunit_size) {
	int crypto_alg_id;
	int slot;
	int err;
	int c;

	crypto_alg_id = ksm->ksm_ll_ops.crypto_alg_find(ksm->ll_priv_data,
						     key_size_bytes,
						     alg, dataunit_size);
	if (crypto_alg_id < 0) {
		return -EINVAL;
	}

	mutex_lock(&ksm->lock);
	slot = ksm->ksm_ll_ops.keyslot_find(ksm->ll_priv_data, key,
					 key_size_bytes, dataunit_size,
					 (unsigned int)crypto_alg_id);
	
	if (slot < 0 && slot != -ENOKEY) {
		mutex_unlock(&ksm->lock);
		return slot;
	}

	BUG_ON(slot >= (int)ksm->num_slots);

	/* Try to use the returned slot */
	if (slot != -ENOKEY) {
		if (unlikely((unsigned int)atomic_read(&ksm->slot_refs[slot]) == UINT_MAX)) {
			mutex_unlock(&ksm->lock);	
			return -EBUSY;
		}

		if (atomic_fetch_inc(&ksm->slot_refs[slot]) == 0) {
			atomic_dec(&ksm->num_free_slots);
		}
		mutex_unlock(&ksm->lock);
		return slot;
	}
	
	/* If we're here, that means there wasn't a slot that
	   was already programmed with the key */

	/* Wait till there is a free slot available */
	while (atomic_read(&ksm->num_free_slots) == 0) {
		mutex_unlock(&ksm->lock);
		wait_event(ksm->wait_queue, (atomic_read(&ksm->num_free_slots) > 0));
		mutex_lock(&ksm->lock);
	}

	/* Todo: fix linear scan? */
	for (c = 0; c < ksm->num_slots; c++) {
		if (atomic_read(&ksm->slot_refs[c]) != 0)
			continue;

		atomic_dec(&ksm->num_free_slots);
		atomic_inc(&ksm->slot_refs[c]);
		err = ksm->ksm_ll_ops.keyslot_program(ksm->ll_priv_data, key,
				   key_size_bytes,
				   dataunit_size,
				   crypto_alg_id,
				   c);		

		if (err) {
			atomic_dec(&ksm->slot_refs[c]);
			atomic_inc(&ksm->num_free_slots);
			wake_up(&ksm->wait_queue);
			mutex_unlock(&ksm->lock);
			return err;
		}
		mutex_unlock(&ksm->lock);
		return c;
	}

	/* We should never get to here */
	BUG();
	return -1;
}
EXPORT_SYMBOL(keyslot_manager_get_slot);

int keyslot_manager_release_slot(struct keyslot_manager *ksm,
								 unsigned int slot) {
	unsigned int prev_refs;

	BUG_ON(slot >= ksm->num_slots);

	prev_refs = atomic_fetch_dec(&ksm->slot_refs[slot]);
	BUG_ON(prev_refs == 0);

	if (prev_refs == 1) {
		atomic_inc(&ksm->num_free_slots);
		wake_up(&ksm->wait_queue);
	}

	return 0;
}
EXPORT_SYMBOL(keyslot_manager_release_slot);

int keyslot_manager_evict_key(struct keyslot_manager *ksm,
			    u8 *key, size_t key_size_bytes,
			    enum keyslot_manager_algs alg,
			    unsigned int dataunit_size) {
	int slot;
	int crypto_alg_id;
	int ret = 1;

	crypto_alg_id = ksm->ksm_ll_ops.crypto_alg_find(ksm->ll_priv_data,
						     key_size_bytes,
						     alg, dataunit_size);
	if (crypto_alg_id < 0) {
		return -EINVAL;
	}

	mutex_lock(&ksm->lock);
	slot = ksm->ksm_ll_ops.keyslot_find(ksm->ll_priv_data, key,
					 key_size_bytes, dataunit_size,
					 (unsigned int)crypto_alg_id);

	if (slot < 0) {
		mutex_unlock(&ksm->lock);
		return slot;
	}

	if (atomic_read(&ksm->slot_refs[slot]) == 0) {
		ret = ksm->ksm_ll_ops.keyslot_evict(ksm->ll_priv_data, slot);
	}

	mutex_unlock(&ksm->lock);
	return ret;
}
EXPORT_SYMBOL(keyslot_manager_evict_key);

void keyslot_manager_destroy(struct keyslot_manager *ksm) {
	kzfree(ksm);
}
EXPORT_SYMBOL(keyslot_manager_destroy);
