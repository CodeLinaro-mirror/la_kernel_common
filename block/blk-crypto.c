// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

/*
 * Refer to Documentation/block/inline-encryption.rst for detailed explanation.
 */

#define pr_fmt(fmt) "blk-crypto: " fmt

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/keyslot-manager.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/slab.h>

#include "blk-crypto-internal.h"

const struct blk_crypto_mode blk_crypto_modes[] = {
	[BLK_ENCRYPTION_MODE_AES_256_XTS] = {
		.cipher_str = "xts(aes)",
		.keysize = 64,
		.ivsize = 16,
	},
	[BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV] = {
		.cipher_str = "essiv(cbc(aes),sha256)",
		.keysize = 16,
		.ivsize = 16,
	},
	[BLK_ENCRYPTION_MODE_ADIANTUM] = {
		.cipher_str = "adiantum(xchacha12,aes)",
		.keysize = 32,
		.ivsize = 32,
	},
};

/*
 * This number needs to be at least (the number of threads doing IO
 * concurrently) * (maximum recursive depth of a bio), so that we don't
 * deadlock on crypt_ctx allocations. The default is chosen to be the same
 * as the default number of post read contexts in both EXT4 and F2FS.
 */
static int num_prealloc_crypt_ctxs = 128;

module_param(num_prealloc_crypt_ctxs, int, 0444);
MODULE_PARM_DESC(num_prealloc_crypt_ctxs,
		"Number of bio crypto contexts to preallocate");

static struct kmem_cache *bio_crypt_ctx_cache;
static mempool_t *bio_crypt_ctx_pool;

static int __init bio_crypt_ctx_init(void)
{
	size_t i;

	bio_crypt_ctx_cache = KMEM_CACHE(bio_crypt_ctx, 0);
	if (!bio_crypt_ctx_cache)
		goto out_no_mem;

	bio_crypt_ctx_pool = mempool_create_slab_pool(num_prealloc_crypt_ctxs,
						      bio_crypt_ctx_cache);
	if (!bio_crypt_ctx_pool)
		goto out_no_mem;

	/* This is assumed in various places. */
	BUILD_BUG_ON(BLK_ENCRYPTION_MODE_INVALID != 0);

	/* Sanity check that no algorithm exceeds the defined limits. */
	for (i = 0; i < BLK_ENCRYPTION_MODE_MAX; i++) {
		BUG_ON(blk_crypto_modes[i].keysize > BLK_CRYPTO_MAX_KEY_SIZE);
		BUG_ON(blk_crypto_modes[i].ivsize > BLK_CRYPTO_MAX_IV_SIZE);
	}

	return 0;
out_no_mem:
	panic("Failed to allocate mem for bio crypt ctxs\n");
}
subsys_initcall(bio_crypt_ctx_init);

void bio_crypt_set_ctx(struct bio *bio, const struct blk_crypto_key *key,
		       const u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE], gfp_t gfp_mask)
{
	struct bio_crypt_ctx *bc = mempool_alloc(bio_crypt_ctx_pool, gfp_mask);

	bc->bc_key = key;
	memcpy(bc->bc_dun, dun, sizeof(bc->bc_dun));

	bio->bi_crypt_context = bc;
}
EXPORT_SYMBOL_GPL(bio_crypt_set_ctx);

void __bio_crypt_free_ctx(struct bio *bio)
{
	mempool_free(bio->bi_crypt_context, bio_crypt_ctx_pool);
	bio->bi_crypt_context = NULL;
}

void __bio_crypt_clone(struct bio *dst, struct bio *src, gfp_t gfp_mask)
{
	dst->bi_crypt_context = mempool_alloc(bio_crypt_ctx_pool, gfp_mask);
	*dst->bi_crypt_context = *src->bi_crypt_context;
}
EXPORT_SYMBOL_GPL(__bio_crypt_clone);

void bio_crypt_dun_increment(u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE],
			     unsigned int inc)
{
	int i = 0;

	while (inc && i < BLK_CRYPTO_DUN_ARRAY_SIZE) {
		dun[i] += inc;
		inc = (dun[i] < inc);
		i++;
	}
}

void __bio_crypt_advance(struct bio *bio, unsigned int bytes)
{
	struct bio_crypt_ctx *bc = bio->bi_crypt_context;

	bio_crypt_dun_increment(bc->bc_dun,
				bytes >> bc->bc_key->data_unit_size_bits);
}

bool bio_crypt_dun_is_contiguous(const struct bio_crypt_ctx *bc,
				 unsigned int bytes,
				 u64 next_dun[BLK_CRYPTO_DUN_ARRAY_SIZE])
{
	int i = 0;
	unsigned int inc = bytes >> bc->bc_key->data_unit_size_bits;

	while (i < BLK_CRYPTO_DUN_ARRAY_SIZE) {
		if (bc->bc_dun[i] + inc != next_dun[i])
			return false;
		/*
		 * If addition of inc to the current entry caused an overflow,
		 * then we have to carry "1" for the next entry - so inc
		 * needs to be "1" for the next loop iteration). Otherwise,
		 * we need inc to be 0 for the next loop iteration. Since
		 * overflow can be determined by (bc->bc_dun[i] + inc)  < inc
		 * we can do the following.
		 */
		inc = ((bc->bc_dun[i] + inc)  < inc);
		i++;
	}

	/*
	 * After going through all the entries in the dun, inc must be 0 for
	 * the duns to be contiguous.
	 */
	return !inc;
}

/*
 * Checks that two bio crypt contexts are compatible - i.e. that
 * they are mergeable except for data_unit_num continuity.
 */
static bool bio_crypt_ctx_compatible(struct bio_crypt_ctx *bc1,
				     struct bio_crypt_ctx *bc2)
{
	if (!bc1)
		return !bc2;

	return bc2 && bc1->bc_key == bc2->bc_key;
}

bool bio_crypt_rq_ctx_compatible(struct request *rq, struct bio *bio)
{
	return bio_crypt_ctx_compatible(rq->crypt_ctx, bio->bi_crypt_context);
}

/*
 * Checks that two bio crypt contexts are compatible, and also
 * that their data_unit_nums are continuous (and can hence be merged)
 * in the order b_1 followed by b_2.
 */
bool bio_crypt_ctx_mergeable(struct bio_crypt_ctx *bc1, unsigned int bc1_bytes,
			     struct bio_crypt_ctx *bc2)
{
	if (!bio_crypt_ctx_compatible(bc1, bc2))
		return false;

	return !bc1 || bio_crypt_dun_is_contiguous(bc1, bc1_bytes, bc2->bc_dun);
}

/*
 * Check that all I/O segments are data unit aligned, and set bio->bi_status
 * on error.
 */
static bool bio_crypt_check_alignment(struct bio *bio)
{
	const unsigned int data_unit_size =
				bio->bi_crypt_context->bc_key->data_unit_size;
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter) {
		if (!IS_ALIGNED(bv.bv_len | bv.bv_offset, data_unit_size)) {
			bio->bi_status = BLK_STS_IOERR;
			return false;
		}
	}

	return true;
}

/**
 * __blk_crypto_init_request - Initializes the request's crypto fields based on
 *			       the blk_crypto_key for a bio to be added to the
 *			       request, and prepares it for hardware inline
 *			       encryption (as opposed to using the crypto API
 *			       fallback).
 *
 * @rq: The request to init
 * @key: The blk_crypto_key of bios that will (eventually) be added to @rq.
 *
 * Initializes the request's crypto fields to appropriate default values and
 * tries to get a keyslot for the blk_crypto_key.
 *
 * Return: BLK_STATUS_OK on success, and negative error code otherwise.
 */
blk_status_t __blk_crypto_init_request(struct request *rq,
				       const struct blk_crypto_key *key)
{
	/*
	 * We have a bio crypt context here - that means we didn't fallback
	 * to crypto API, so try to program a keyslot now.
	 */
	return blk_ksm_get_slot_for_key(rq->q->ksm, key, &rq->crypt_keyslot);
}

/**
 * __blk_crypto_free_request - Uninitialize the crypto fields of a request.
 *
 * @rq: The request whose crypto fields to uninitialize.
 *
 * Completely uninitializes the crypto fields of a request. If a keyslot has
 * been programmed into some inline encryption hardware, that keyslot is
 * released. The rq->crypt_ctx is also freed.
 */
void __blk_crypto_free_request(struct request *rq)
{
	blk_ksm_put_slot(rq->crypt_keyslot);
	mempool_free(rq->crypt_ctx, bio_crypt_ctx_pool);
	blk_crypto_rq_set_defaults(rq);
}

/**
 * __blk_crypto_bio_prep - Prepare bio for inline encryption
 *
 * @bio_ptr: pointer to original bio pointer
 *
 * If the bio crypt context provided for the bio is supported by the underlying
 * device's inline encryption hardware, do nothing.
 *
 * Otherwise, try to perform en/decryption for this bio by falling back to the
 * kernel crypto API. When the crypto API fallback is used for encryption,
 * blk-crypto may choose to split the bio into 2 - the first one that will
 * continue to be processed and the second one that will be resubmitted via
 * generic_make_request. A bounce bio will be allocated to encrypt the contents
 * of the aforementioned "first one", and *bio_ptr will be updated to this
 * bounce bio.
 *
 * Caller must ensure bio has bio_crypt_ctx.
 *
 * Return: true on success; false on error (and bio->bi_status will be set
 *	   appropriately, and bio_endio() will have been called so bio
 *	   submission should abort).
 */
bool __blk_crypto_bio_prep(struct bio **bio_ptr)
{
	struct bio *bio = *bio_ptr;

	/* Error if bio has no data. */
	if (WARN_ON_ONCE(!bio_has_data(bio)))
		goto fail;

	if (!bio_crypt_check_alignment(bio))
		goto fail;

	/*
	 * Success if device supports the encryption context, or we succeeded
	 * in falling back to the crypto API.
	 */
	if (blk_ksm_crypto_key_supported(bio->bi_disk->queue->ksm,
					 bio->bi_crypt_context->bc_key))
		return true;

	if (blk_crypto_fallback_bio_prep(bio_ptr))
		return true;
fail:
	bio_endio(*bio_ptr);
	return false;
}

/**
 * __blk_crypto_rq_bio_prep - Prepare a request when its first bio is inserted
 *
 * @rq: The request to prepare
 * @bio: The first bio being inserted into the request
 *
 * Frees the bio crypt context in the request's old rq->crypt_ctx, if any, and
 * moves the bio crypt context of the bio into the request's rq->crypt_ctx.
 */
void __blk_crypto_rq_bio_prep(struct request *rq, struct bio *bio)
{
	mempool_free(rq->crypt_ctx, bio_crypt_ctx_pool);
	rq->crypt_ctx = bio->bi_crypt_context;
	bio->bi_crypt_context = NULL;
}

void __blk_crypto_rq_prep_clone(struct request *dst, struct request *src)
{
	/* Don't clone crypto info if src uses fallback en/decryption */
	if (!src->crypt_keyslot)
		return;

	dst->crypt_ctx = src->crypt_ctx;
}

/**
 * __blk_crypto_insert_cloned_request - Prepare a cloned request to be inserted
 *					into a request queue.
 * @rq: the request being queued
 *
 * Return: BLK_STS_OK on success, nonzero on error.
 */
blk_status_t __blk_crypto_insert_cloned_request(struct request *rq)
{
	return blk_crypto_init_request(rq, rq->crypt_ctx->bc_key);
}

/**
 * blk_crypto_init_key() - Prepare a key for use with blk-crypto
 * @blk_key: Pointer to the blk_crypto_key to initialize.
 * @raw_key: Pointer to the raw key.
 * @raw_key_size: Size of raw key.  Must be at least the required size for the
 *                chosen @crypto_mode; see blk_crypto_modes[].  (It's allowed
 *                to be longer than the mode's actual key size, in order to
 *                support inline encryption hardware that accepts wrapped keys.
 *                @is_hw_wrapped has to be set for such keys)
 * @is_hw_wrapped: Denotes @raw_key is wrapped.
 * @crypto_mode: identifier for the encryption algorithm to use
 * @dun_bytes: number of bytes that will be used to specify the DUN when this
 *	       key is used
 * @data_unit_size: the data unit size to use for en/decryption
 *
 * Return: 0 on success, -errno on failure.  The caller is responsible for
 *	   zeroizing both blk_key and raw_key when done with them.
 */
int blk_crypto_init_key(struct blk_crypto_key *blk_key,
			const u8 *raw_key, unsigned int raw_key_size,
			bool is_hw_wrapped,
			enum blk_crypto_mode_num crypto_mode,
			unsigned int dun_bytes,
			unsigned int data_unit_size)
{
	const struct blk_crypto_mode *mode;
	static siphash_key_t hash_key;

	memset(blk_key, 0, sizeof(*blk_key));

	if (crypto_mode >= ARRAY_SIZE(blk_crypto_modes))
		return -EINVAL;

	BUILD_BUG_ON(BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE < BLK_CRYPTO_MAX_KEY_SIZE);

	mode = &blk_crypto_modes[crypto_mode];
	if (is_hw_wrapped) {
		if (raw_key_size < mode->keysize ||
		    raw_key_size > BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE)
			return -EINVAL;
	} else {
		if (raw_key_size != mode->keysize)
			return -EINVAL;
	}

	if (!is_power_of_2(data_unit_size))
		return -EINVAL;

	blk_key->crypto_mode = crypto_mode;
	blk_key->dun_bytes = dun_bytes;
	blk_key->data_unit_size = data_unit_size;
	blk_key->data_unit_size_bits = ilog2(data_unit_size);
	blk_key->size = raw_key_size;
	blk_key->is_hw_wrapped = is_hw_wrapped;
	memcpy(blk_key->raw, raw_key, raw_key_size);

	/*
	 * The keyslot manager uses the SipHash of the key to implement O(1) key
	 * lookups while avoiding leaking information about the keys.  It's
	 * precomputed here so that it only needs to be computed once per key.
	 */
	get_random_once(&hash_key, sizeof(hash_key));
	blk_key->hash = siphash(raw_key, raw_key_size, &hash_key);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_crypto_init_key);

/**
 * blk_crypto_evict_key() - Evict a key from any inline encryption hardware
 *			    it may have been programmed into
 * @q: The request queue who's keyslot manager this key might have been
 *     programmed into
 * @key: The key to evict
 *
 * Upper layers (filesystems) should call this function to ensure that a key
 * is evicted from hardware that it might have been programmed into. This
 * will call blk_ksm_evict_key on the queue's keyslot manager, if one
 * exists, and supports the crypto algorithm with the specified data unit size.
 * Otherwise, it will evict the key from the blk-crypto-fallback's ksm.
 *
 * Return: 0 on success or if key is not present in the q's ksm, -err on error.
 */
int blk_crypto_evict_key(struct request_queue *q,
			 const struct blk_crypto_key *key)
{
	if (q->ksm && blk_ksm_crypto_key_supported(q->ksm, key))
		return blk_ksm_evict_key(q->ksm, key);

	return blk_crypto_fallback_evict_key(key);
}
EXPORT_SYMBOL_GPL(blk_crypto_evict_key);
