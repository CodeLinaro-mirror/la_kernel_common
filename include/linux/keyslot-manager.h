/**
	TODO: licenses in all files

*/

#ifndef __LINUX_KEYSLOT_MANAGER_H
#define __LINUX_KEYSLOT_MANAGER_H

#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/types.h>

enum keyslot_manager_algs {
	UNSUPPORTED_ALG,
	AES_XTS,
	BITLOCKER_AES_CBC,
	AES_ECB,
	ESSIV_AES_CBC,
};

struct keyslot_mgmt_ll_ops {
	int (* keyslot_program)(void *ll_priv_data, u8 *key, size_t key_size_bytes,
				unsigned int dataunit_size,
				unsigned int alg_type, /* As returned by crypto alg find */
				unsigned int slot);
	int (* keyslot_release)(void *ll_priv_data, unsigned int slot);
	int (* crypto_alg_find)(void *ll_priv_data, size_t key_size_bytes,
				enum keyslot_manager_algs alg, unsigned int dataunit_size);
	/* Returns the slot number that matches the key, or -ENOKEY if no match found, or
	   negative on error */
	int (* keyslot_find)(void *ll_priv_data, u8 *key, size_t key_size_bytes,
			     unsigned int dataunit_size, unsigned int alg_type);
	/* Returns 0 on success, negative on error */
	int (* keyslot_evict)(void *ll_priv_data, unsigned int slot);
};

struct keyslot_manager {
	unsigned int num_slots;
	atomic_t *slot_refs;
	atomic_t num_free_slots;
	struct keyslot_mgmt_ll_ops ksm_ll_ops;
	void *ll_priv_data;
	struct mutex lock;
	wait_queue_head_t wait_queue;
};

extern struct keyslot_manager *keyslot_manager_create(unsigned int num_slots,
					struct keyslot_mgmt_ll_ops *ksm_ops,
					void *ll_priv_data);

extern int keyslot_manager_get_slot(struct keyslot_manager *ksm,
			    u8 *key, size_t key_size_bytes,
			    enum keyslot_manager_algs alg,
			    unsigned int dataunit_size);

extern int keyslot_manager_release_slot(struct keyslot_manager *ksm,
										unsigned int slot);

extern int keyslot_manager_evict_key(struct keyslot_manager *ksm,
			    u8 *key, size_t key_size_bytes,
			    enum keyslot_manager_algs alg,
			    unsigned int dataunit_size);

extern void keyslot_manager_destroy(struct keyslot_manager *ksm);

#endif /* __LINUX_KEYSLOT_MANAGER_H */
