// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_BLK_CRYPTO_H
#define __LINUX_BLK_CRYPTO_H

#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>

struct blk_crypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	size_t keysize;
	size_t ivsize;
	bool needs_essiv;
};

extern struct blk_crypt_mode blk_crypt_modes[];

#ifdef CONFIG_BLK_CRYPTO

int blk_crypto_init(void);

int blk_crypto_submit_bio(struct bio *bio);

int blk_crypto_endio(struct bio *bio);

#else /* CONFIG_BLK_CRYPTO */

static inline int blk_crypto_init(void)
{
	return 0;
}

static inline int blk_crypto_submit_bio(struct bio *bio)
{
	return 0;
}

static inline int blk_crypto_endio(struct bio *bio)
{
	return 0;
}

#endif /* CONFIG_BLK_CRYPTO */

#endif /* __LINUX_BLK_CRYPTO_H */
