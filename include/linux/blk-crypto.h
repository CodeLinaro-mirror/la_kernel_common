// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_BLK_CRYPTO_H
#define __LINUX_BLK_CRYPTO_H

#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>

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
