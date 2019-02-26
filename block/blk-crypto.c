// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */
#include <linux/blk-crypto.h>
#include <linux/keyslot-manager.h>
#include <linux/mempool.h>
#include <crypto/skcipher.h>
#include <crypto/aes.h>
#include <linux/swab.h>
#include <crypto/algapi.h>

struct blk_crypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	size_t keysize;
	size_t ivsize;
	bool needs_essiv;
};

static const struct blk_crypt_mode blk_crypt_modes[] = {
	[BLK_ENCRYPTION_MODE_AES_256_XTS] = {
		.friendly_name = "AES-256-XTS",
		.cipher_str = "xts(aes)",
		.keysize = 64,
		.ivsize = 16,
	},
	/* TODO: the rest of the algs that fscrypt supports */
};

#define BLK_CRYPTO_MAX_KEY_SIZE 64
/* TODO: Do we want to make this user configurable somehow? */
#define BLK_CRYPTO_NUM_KEYSLOTS 100

static struct blk_crypto_keyslot {
	struct crypto_skcipher *tfm;
	int crypto_alg_id;
	union {
		u8 key[BLK_CRYPTO_MAX_KEY_SIZE];
		u32 key_words[BLK_CRYPTO_MAX_KEY_SIZE/4];
	};
} *slot_mem;

struct work_mem {
	struct work_struct crypto_work;
	struct bio *bio;
};

static struct keyslot_manager *blk_crypto_ksm;
static struct workqueue_struct *blk_crypto_wq;
static mempool_t *blk_crypto_page_pool;
static struct kmem_cache *blk_crypto_work_mem_cache;

static unsigned int num_prealloc_bounce_pg = 32;

/* TODO: handle modes that need essiv */
static int blk_crypto_keyslot_program(void *priv, const u8 *key,
			      unsigned int data_unit_size,
			      unsigned int crypto_alg_id,
			      unsigned int slot)
{
	struct crypto_skcipher *tfm = slot_mem[slot].tfm;
	int err;
	size_t keysize = blk_crypt_modes[crypto_alg_id].keysize;

	if (crypto_alg_id != slot_mem[slot].crypto_alg_id || !tfm) {
		crypto_free_skcipher(slot_mem[slot].tfm);
		slot_mem[slot].tfm = NULL;
		slot_mem[slot].crypto_alg_id = crypto_alg_id;
		tfm = crypto_alloc_skcipher(
			blk_crypt_modes[crypto_alg_id].cipher_str, 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);

		crypto_skcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
		slot_mem[slot].tfm = tfm;
	}


	err = crypto_skcipher_setkey(tfm, key, keysize);

	if (err) {
		crypto_free_skcipher(slot_mem[slot].tfm);
		slot_mem[slot].tfm = NULL;
		return err;
	}

	memcpy(slot_mem[slot].key, key, keysize);

	return 0;
}

static int blk_crypto_keyslot_evict(void *priv, unsigned int slot,
				    const u8 *key,
				    unsigned int data_unit_size,
				    unsigned int crypto_alg_id)
{
	crypto_free_skcipher(slot_mem[slot].tfm);
	slot_mem[slot].tfm = NULL;
	memset(slot_mem[slot].key, 0, BLK_CRYPTO_MAX_KEY_SIZE);

	return 0;
}

static int blk_crypto_keyslot_find(void *priv,
				   const u8 *key,
				   unsigned int data_unit_size_bytes,
				   unsigned int crypto_alg_id)
{
	int slot;

	/* TODO: hashmap? */
	for (slot = 0; slot < BLK_CRYPTO_NUM_KEYSLOTS; slot++) {
		if (slot_mem[slot].crypto_alg_id == crypto_alg_id &&
		    crypto_memneq(slot_mem[slot].key, key,
			blk_crypt_modes[crypto_alg_id].keysize) == 0) {
			return slot;
		}
	}

	return -ENOKEY;
}

static int blk_crypto_alg_find(void *priv,
			       enum blk_crypt_mode_index crypt_mode,
			       unsigned int data_unit_size)
{
	/**
	 * Blk-crypto supports all data unit sizes, so we can use
	 * the crypt_mode directly as the internal crypto_alg_id.
	 * Refer to comment in keyslot_manager.h for details
	 * on this crypto_alg_id.
	 */
	return crypt_mode;
}

const struct keyslot_mgmt_ll_ops blk_crypto_ksm_ll_ops = {
	.keyslot_program	= blk_crypto_keyslot_program,
	.keyslot_evict		= blk_crypto_keyslot_evict,
	.keyslot_find		= blk_crypto_keyslot_find,
	.crypto_alg_find	= blk_crypto_alg_find,
};

static void blk_crypto_release_keyslot(struct bio *bio)
{
	struct bio_crypt_ctx *crypt_ctx = &bio->bi_crypt_context;

	keyslot_manager_put_slot(crypt_ctx->processing_ksm,
				 crypt_ctx->keyslot);
	bio_crypt_unset_keyslot(bio);
}

static int blk_crypto_program_keyslot(struct bio *bio,
				      struct keyslot_manager *ksm)
{
	int slot;
	enum blk_crypt_mode_index crypt_mode = bio_crypt_mode(bio);

	slot = keyslot_manager_get_slot_for_key(ksm,
						bio_crypt_raw_key(bio),
						crypt_mode, PAGE_SIZE);
	if (slot >= 0) {
		bio_crypt_set_keyslot(bio, slot, ksm);
		return 0;
	}

	return slot;
}

static int blk_crypto_encrypt_bio(struct bio *bio)
{
	int slot = bio_crypt_get_slot(bio);
	struct skcipher_request *ciph_req = NULL;
	struct crypto_wait wait;
	struct bio_vec bv;
	struct bvec_iter iter;
	int err = 0;
	__le64 curr_dun;
	union {
		__le64 dun;
		u8 bytes[16];
	} iv;
	struct scatterlist src, dst;

	curr_dun = cpu_to_le64(bio_crypt_data_unit_num(bio));

	ciph_req = skcipher_request_alloc(slot_mem[slot].tfm, GFP_NOFS);
	if (!ciph_req) {
		bio->bi_status = BLK_STS_RESOURCE;
		err = -ENOMEM;
		goto out_ciph_req;
	}

	skcipher_request_set_callback(ciph_req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);

	sg_init_table(&src, 1);
	sg_init_table(&dst, 1);
	bio_for_each_segment(bv, bio, iter) {
		struct page *page = bv.bv_page;
		struct page *ciphertext_page =
			mempool_alloc(blk_crypto_page_pool, GFP_NOFS);

		memset(&iv, 0, sizeof(iv));
		iv.dun = curr_dun;

		/* TODO: fix */
		if (!ciphertext_page) {
			bio->bi_status = BLK_STS_IOERR;
			err = -EIO;
			goto out;
		}

		SetPagePrivate(ciphertext_page);
		set_page_private(ciphertext_page, (unsigned long)page);
		lock_page(ciphertext_page);
		bio_iter_page(bio, iter) = ciphertext_page;

		sg_set_page(&src, page, bv.bv_len, bv.bv_offset);
		sg_set_page(&dst, ciphertext_page, bv.bv_len, bv.bv_offset);
		skcipher_request_set_crypt(ciph_req, &src, &dst,
					   bv.bv_len, iv.bytes);
		crypto_init_wait(&wait);
		err = crypto_wait_req(crypto_skcipher_encrypt(ciph_req), &wait);
		if (err) {
			bio->bi_status = BLK_STS_IOERR;
			err = -EIO;
			goto out;
		}
		le64_add_cpu(&curr_dun, 1);
	}

out:
	skcipher_request_free(ciph_req);
out_ciph_req:
	return err;
}

/* TODO: assumption right now is:
 * each segment in bio has length == the data_unit_size
 */
static void blk_crypto_decrypt_bio(struct work_struct *w)
{
	struct work_mem *work_mem =
		container_of(w, struct work_mem, crypto_work);
	struct bio *bio = work_mem->bio;
	int slot = bio_crypt_get_slot(bio);
	struct skcipher_request *ciph_req;
	struct crypto_wait wait;
	struct bio_vec bv;
	struct bvec_iter iter;
	__le64 curr_dun;
	union {
		__le64 dun;
		u8 bytes[16];
	} iv;
	struct scatterlist src;

	curr_dun = cpu_to_le64(bio_crypt_data_unit_num(bio) -
			       bio->bi_iter.bi_idx +
			       bio->bi_crypt_context.crypt_iter.bi_idx);

	kmem_cache_free(blk_crypto_work_mem_cache, work_mem);
	ciph_req = skcipher_request_alloc(slot_mem[slot].tfm, GFP_NOFS);
	if (!ciph_req) {
		bio->bi_status = BLK_STS_RESOURCE;
		goto out_ciph_req;
	}

	skcipher_request_set_callback(ciph_req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);

	sg_init_table(&src, 1);
	__bio_for_each_segment(bv, bio, iter,
			       bio->bi_crypt_context.crypt_iter) {
		struct page *page = bv.bv_page;
		int err;

		memset(&iv, 0, sizeof(iv));
		iv.dun = curr_dun;

		sg_set_page(&src, page, bv.bv_len, bv.bv_offset);
		skcipher_request_set_crypt(ciph_req, &src, &src,
					   bv.bv_len, iv.bytes);
		crypto_init_wait(&wait);
		err = crypto_wait_req(crypto_skcipher_decrypt(ciph_req), &wait);
		if (err) {
			bio->bi_status = BLK_STS_IOERR;
			goto out;
		}
		le64_add_cpu(&curr_dun, 1);
	}

out:
	skcipher_request_free(ciph_req);
out_ciph_req:
	blk_crypto_release_keyslot(bio);
	bio_endio(bio);
}

static void blk_crypto_queue_decrypt_bio(struct bio *bio)
{
	struct work_mem *work_mem =
		kmem_cache_zalloc(blk_crypto_work_mem_cache, GFP_ATOMIC);

	if (!work_mem) {
		bio->bi_status = BLK_STS_RESOURCE;
		return bio_endio(bio);
	}

	INIT_WORK(&work_mem->crypto_work, blk_crypto_decrypt_bio);
	work_mem->bio = bio;
	queue_work(blk_crypto_wq, &work_mem->crypto_work);
}

/**
 * Ensures that:
 * 1) The bio’s encryption context is programmed into a keyslot in the
 * keyslot manager (KSM) of the request queue that the bio is being submitted
 * to (or the software fallback KSM if the request queue doesn’t have a KSM),
 * and that the processing_ksm in the bi_crypt_context of this bio is set to
 * this KSM.
 *
 * 2) That the bio has a reference to this keyslot in this KSM.
 */
int blk_crypto_submit_bio(struct bio *bio)
{
	struct request_queue *q;
	int err;
	enum blk_crypt_mode_index crypt_mode;
	struct bio_crypt_ctx *crypt_ctx;

	if (!bio_has_data(bio))
		return 0;

	if (!bio_is_encrypted(bio) || bio_crypt_swhandled(bio))
		return 0;

	crypt_ctx = &bio->bi_crypt_context;
	q = bio->bi_disk->queue;
	crypt_mode = bio_crypt_mode(bio);

	if (bio_crypt_has_keyslot(bio)) {
		if (q->ksm) {
			if (q->ksm == crypt_ctx->processing_ksm)
				return 0;

			blk_crypto_release_keyslot(bio);

			err = blk_crypto_program_keyslot(bio, q->ksm);
			if (!err)
				return 0;
			/* Fallback to software */
		} else {
			/**
			 * We have been lied to. A device on upper layer
			 * claimed to support ICE, but passed the crypt
			 * ctx to a device below that doesn't claim to
			 * support ICE, and the upper layer itself didn't
			 * handle the crypt either. If this was the bio that
			 * set up the keyslot, free it up. In either case,
			 * fallback to software.
			 */
			blk_crypto_release_keyslot(bio);
		}
	} else if (q->ksm) {
		/**
		 * We haven't programmed the key anywhere,
		 * and the device claims to have ICE.
		 * Try using it.
		 */
		err = blk_crypto_program_keyslot(bio, q->ksm);
		if (!err)
			return 0;
	}

	/* Fallback to software crypto */
	err = blk_crypto_program_keyslot(bio, blk_crypto_ksm);
	if (err)
		goto out_err;
	bio_crypt_set_swhandled(bio);
	if (bio_data_dir(bio) == WRITE) {
		/* Encrypt the data now */
		err = blk_crypto_encrypt_bio(bio);
		if (err)
			goto out_encrypt_err;
	}
	return 0;
out_err:
	bio->bi_status = BLK_STS_IOERR;
out_encrypt_err:
	bio_endio(bio);
	return err;
}

/**
 * If the bio is not en/decrypted in software, this function releases the
 * reference to the keyslot that blk_crypto_submit_bio got.
 * If blk_crypto_submit_bio decided to fallback to software crypto for this
 * bio, then if the bio is doing a write, we free the allocated bounce pages,
 * and if the bio is doing a read, we queue the bio for decryption into a
 * workqueue and return -EAGAIN. After the bio has been decrypted, we release
 * the keyslot before we call bio_endio(bio).
 */
int blk_crypto_endio(struct bio *bio)
{
	struct bio_crypt_ctx *crypt_ctx;

	if (!bio_crypt_has_keyslot(bio))
		return 0;

	crypt_ctx = &bio->bi_crypt_context;

	if (!bio_crypt_swhandled(bio)) {
		blk_crypto_release_keyslot(bio);
		return 0;
	}

	if (bio_data_dir(bio) == WRITE) {
		/* restore bio pages and free bounce pages */
		struct bio_vec bv;
		struct bvec_iter iter;

		__bio_for_each_segment(bv, bio, iter,
				       bio->bi_crypt_context.crypt_iter) {
			struct page *ciphertext_page = bv.bv_page;
			struct page *page;

			page = (struct page *)page_private(ciphertext_page);
			bio_iter_page(bio, iter) = page;

			set_page_private(ciphertext_page, (unsigned long)NULL);
			ClearPagePrivate(ciphertext_page);
			unlock_page(ciphertext_page);
			mempool_free(ciphertext_page, blk_crypto_page_pool);
		}

		blk_crypto_release_keyslot(bio);
		return 0;
	}

	/* bio_data_dir(bio) == READ. So decrypt bio */
	blk_crypto_queue_decrypt_bio(bio);
	return -EAGAIN;
}

int __init blk_crypto_init(void)
{
	blk_crypto_ksm = keyslot_manager_create(BLK_CRYPTO_NUM_KEYSLOTS,
				       &blk_crypto_ksm_ll_ops,
				       NULL);
	if (!blk_crypto_ksm)
		goto out_ksm;

	blk_crypto_wq = alloc_workqueue("blk_crypto_wq",
			       WQ_UNBOUND | WQ_HIGHPRI,
			       num_online_cpus());
	if (!blk_crypto_wq)
		goto out_wq;

	slot_mem = kzalloc(sizeof(*slot_mem) * BLK_CRYPTO_NUM_KEYSLOTS,
			   GFP_KERNEL);
	if (!slot_mem)
		goto out_slot_mem;

	blk_crypto_page_pool =
		mempool_create_page_pool(num_prealloc_bounce_pg, 0);
	if (!blk_crypto_page_pool)
		goto out_bounce_pool;

	blk_crypto_work_mem_cache = KMEM_CACHE(work_mem, SLAB_RECLAIM_ACCOUNT);
	if (!blk_crypto_work_mem_cache)
		goto out_work_mem_cache;

	return 0;

out_work_mem_cache:
	mempool_destroy(blk_crypto_page_pool);
	blk_crypto_page_pool = NULL;
out_bounce_pool:
	kzfree(slot_mem);
	slot_mem = NULL;
out_slot_mem:
	destroy_workqueue(blk_crypto_wq);
	blk_crypto_wq = NULL;
out_wq:
	keyslot_manager_destroy(blk_crypto_ksm);
	blk_crypto_ksm = NULL;
out_ksm:
	pr_warn("No memory for block crypto software fallback.");
	return -ENOMEM;
}
