// SPDX-License-Identifier: GPL-2.0
/*
 * This contains encryption functions for per-file encryption.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility
 *
 * Written by Michael Halcrow, 2014.
 *
 * Filename encryption additions
 *	Uday Savagaonkar, 2014
 * Encryption policy handling additions
 *	Ildar Muslukhov, 2014
 * Add fscrypt_pullback_bio_page()
 *	Jaegeuk Kim, 2015.
 *
 * This has not yet undergone a rigorous security audit.
 *
 * The usage of AES-XTS should conform to recommendations in NIST
 * Special Publication 800-38E and IEEE P1619/D16.
 */

#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/namei.h>
#include <linux/keyslot-manager.h>
#include <linux/blkdev.h>
#include <crypto/algapi.h>
#include "fscrypt_private.h"

static void __fscrypt_decrypt_bio(struct bio *bio, bool done, bool decrypt)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;
		int ret = 0;

		if (decrypt) {
			ret = fscrypt_decrypt_page(page->mapping->host, page,
						   PAGE_SIZE, 0, page->index);
		}
		if (ret) {
			WARN_ON_ONCE(1);
			SetPageError(page);
		} else if (done) {
			SetPageUptodate(page);
		}
		if (done)
			unlock_page(page);
	}
}

void fscrypt_decrypt_bio(struct bio *bio)
{
	__fscrypt_decrypt_bio(bio, false, true);
}
EXPORT_SYMBOL(fscrypt_decrypt_bio);

static void completion_pages(struct work_struct *work)
{
	struct fscrypt_ctx *ctx =
		container_of(work, struct fscrypt_ctx, r.work);
	struct bio *bio = ctx->r.bio;

	__fscrypt_decrypt_bio(bio, true, true);
	fscrypt_release_ctx(ctx);
	bio_put(bio);
}

static void decrypt_bio_hwcrypt(struct fscrypt_ctx *ctx, struct bio *bio)
{
	__fscrypt_decrypt_bio(bio, true, false);
	fscrypt_release_ctx(ctx);
	bio_put(bio);
}

void fscrypt_enqueue_decrypt_bio(struct fscrypt_ctx *ctx, struct bio *bio)
{
	if (bio_is_encrypted(bio)) {
		decrypt_bio_hwcrypt(ctx, bio);
	} else {
		INIT_WORK(&ctx->r.work, completion_pages);
		ctx->r.bio = bio;
		fscrypt_enqueue_decrypt_work(&ctx->r.work);
	}
}
EXPORT_SYMBOL(fscrypt_enqueue_decrypt_bio);

void fscrypt_pullback_bio_page(struct page **page, bool restore)
{
	struct fscrypt_ctx *ctx;
	struct page *bounce_page;

	/* The bounce data pages are unmapped. */
	if ((*page)->mapping)
		return;

	/* The bounce data page is unmapped. */
	bounce_page = *page;
	ctx = (struct fscrypt_ctx *)page_private(bounce_page);

	/* restore control page */
	*page = ctx->w.control_page;

	if (restore)
		fscrypt_restore_control_page(bounce_page);
}
EXPORT_SYMBOL(fscrypt_pullback_bio_page);

int fscrypt_zeroout_range(const struct inode *inode, pgoff_t lblk,
				sector_t pblk, unsigned int len)
{
	struct fscrypt_ctx *ctx = NULL;
	struct page *ciphertext_page = NULL;
	struct bio *bio;
	int ret, err = 0;

	BUG_ON(inode->i_sb->s_blocksize != PAGE_SIZE);

	if (!fscrypt_inode_is_hw_encrypted(inode)) {
		ctx = fscrypt_get_ctx(inode, GFP_NOFS);
		if (IS_ERR(ctx))
			return PTR_ERR(ctx);

		ciphertext_page = fscrypt_alloc_bounce_page(ctx, GFP_NOWAIT);
		if (IS_ERR(ciphertext_page)) {
			err = PTR_ERR(ciphertext_page);
			goto errout;
		}
	}

	while (len--) {
		if (!fscrypt_inode_is_hw_encrypted(inode)) {
			err = fscrypt_do_page_crypto(inode, FS_ENCRYPT, lblk,
					     ZERO_PAGE(0), ciphertext_page,
					     PAGE_SIZE, 0, GFP_NOFS);
			if (err)
				goto errout;
		}

		bio = bio_alloc(GFP_NOWAIT, 1);
		if (!bio) {
			err = -ENOMEM;
			goto errout;
		}
		bio_set_dev(bio, inode->i_sb->s_bdev);
		bio->bi_iter.bi_sector =
			pblk << (inode->i_sb->s_blocksize_bits - 9);
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		if (!fscrypt_inode_is_hw_encrypted(inode)) {
			ret = bio_add_page(bio, ciphertext_page,
						inode->i_sb->s_blocksize, 0);
		} else {
			ret = bio_add_page(bio, ZERO_PAGE(0),
						inode->i_sb->s_blocksize, 0);
		}

		if (ret != inode->i_sb->s_blocksize) {
			/* should never happen! */
			WARN_ON(1);
			bio_put(bio);
			err = -EIO;
			goto errout;
		}
		fscrypt_set_bio_crypt_ctx(inode, bio, pblk);
		err = submit_bio_wait(bio);
		if (err == 0 && bio->bi_status)
			err = -EIO;
		bio_put(bio);
		if (err)
			goto errout;
		lblk++;
		pblk++;
	}
	err = 0;
errout:
	if (!fscrypt_inode_is_hw_encrypted(inode))
		fscrypt_release_ctx(ctx);
	return err;
}
EXPORT_SYMBOL(fscrypt_zeroout_range);

#if IS_ENABLED(CONFIG_FS_ENCRYPTION_HW_CRYPT)
static enum blk_crypt_mode_index
get_blk_crypto_alg_for_fscryptalg(u8 fscrypt_alg)
{
	switch (fscrypt_alg) {
	case FS_ENCRYPTION_MODE_AES_256_XTS:
		return BLK_ENCRYPTION_MODE_AES_256_XTS;
	default: return -EINVAL;
	}
}

int fscrypt_set_bio_crypt_ctx(const struct inode *inode,
				 struct bio *bio, u64 data_unit_num)
{
	struct fscrypt_info *ci = inode->i_crypt_info;

	/* If inode is not hw encrypted, nothing to do. */
	if (!fscrypt_inode_is_hw_encrypted(inode))
		return 0;

	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode))
		return -1;

	bio_crypt_set_ctx(bio, ci->ci_master_key->mk_raw,
			  get_blk_crypto_alg_for_fscryptalg(ci->ci_data_mode),
			  data_unit_num,
			  PAGE_SHIFT);
	return 0;
}
EXPORT_SYMBOL(fscrypt_set_bio_crypt_ctx);

int fscrypt_evict_crypt_key(struct inode *inode)
{
	struct request_queue *q;
	struct fscrypt_info *ci;

	if (!inode)
		return 0;

	q = inode->i_sb->s_bdev->bd_queue;
	ci = inode->i_crypt_info;

	if (!q || !q->ksm || !ci ||
	    !fscrypt_inode_is_hw_encrypted(inode)) {
		return 0;
	}

	return keyslot_manager_evict_key(q->ksm,
					 ci->ci_master_key->mk_raw,
					 get_blk_crypto_alg_for_fscryptalg(
						ci->ci_data_mode),
					 PAGE_SIZE);
}
EXPORT_SYMBOL(fscrypt_evict_crypt_key);

bool fscrypt_inode_crypt_mergeable(const struct inode *inode_1,
				   const struct inode *inode_2)
{
	struct fscrypt_info *ci_1, *ci_2;
	bool enc_1 = fscrypt_inode_is_hw_encrypted(inode_1);
	bool enc_2 = fscrypt_inode_is_hw_encrypted(inode_2);

	if (enc_1 != enc_2)
		return false;

	if (!enc_1)
		return true;

	if (inode_1 == inode_2)
		return true;

	ci_1 = inode_1->i_crypt_info;
	ci_2 = inode_2->i_crypt_info;

	return ci_1->ci_data_mode == ci_2->ci_data_mode &&
	       crypto_memneq(ci_1->ci_master_key->mk_raw,
			     ci_2->ci_master_key->mk_raw,
			     ci_1->ci_master_key->mk_mode->keysize) == 0;
}
EXPORT_SYMBOL(fscrypt_inode_crypt_mergeable);

#endif /* FS_ENCRYPTION_HW_CRYPT */
