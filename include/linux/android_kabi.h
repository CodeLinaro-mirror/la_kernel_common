/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * android_kabi.h - Android kernel abi abstraction header
 *
 * Copyright (C) 2020 Google, Inc.
 *
 * Heavily influenced by rh_kabi.h which came from the RHEL/CENTOS kernel and
 * was:
 *	Copyright (c) 2014 Don Zickus
 *	Copyright (c) 2015-2018 Jiri Benc
 *	Copyright (c) 2015 Sabrina Dubroca, Hannes Frederic Sowa
 *	Copyright (c) 2016-2018 Prarit Bhargava
 *	Copyright (c) 2017 Paolo Abeni, Larry Woodman
 *
 * These macros are to be used to try to help alivate future kernel abi changes
 * that will occur as LTS and other kernel patches are merged into the tree
 * during a period in which the kernel abi is wishing to not be disturbed.
 *
 * There are two times these macros should be used:
 *  - Before the kernel abi is "frozen"
 *    Padding can be added to various kernel structures that have in the past
 *    been known to change over time.  That will give "room" in the structure
 *    that can then be used when fields are added so that the structure size
 *    will not change.
 *
 *  - After the kernel abi is "frozen"
 *    If a structure's field is changed to a type that is identical in size to
 *    the previous type, it can be changed with a union macro
 *    If a field is added to a structure, the padding fields can be used to add
 *    the new field in a "safe" way.
 */
#ifndef _ANDROID_KABI_H
#define _ANDROID_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>

/* Enable this variable if the ABI is now frozen */
// #define ANDROID_ABI_FROZEN


#ifdef ANDROID_ABI_FROZEN
#define ANDROID_KABI_RENAME(_orig, _new)	_orig
#define _ANDROID_KABI_REPLACE(_orig, _new)	_orig
#define _ANDROID_KABI_RESERVE(n)		u64 android_kabi_reserved##n

#else

#define ANDROID_KABI_RENAME(_orig, _new)	_new
#define _ANDROID_KABI_REPLACE(_orig, _new)		\
	union {						\
		_new;					\
		struct {				\
			_orig;				\
		} __UNIQUE_ID(android_kabi_hide);

#define _ANDROID_KABI_RESERVE(n)
#endif	/* ANDROID_ABI_FROZEN */

/*
 * Macros to use _before_ the ABI is frozen
 */
/* Reserve some "padding" in a structure for potential future use */
#define ANDROID_KABI_RESERVE(n)		_ANDROID_KABI_RESERVE(n);


/*
 * Macros to use _after_ the ABI is frozen
 */

/* Use a previously defined padding variable for a new field in a structure */
#define ANDROID_KABI_USE(n, _new)		\
	ANDROID_KABI_REPLACE(_ANDROID_KABI_RESERVE(n), n)

/* Use a previously defined padding variable for multiple fields in a structure */
/* Note, when using this, the size of the new fields added together must equal
 * 64 bits
 */
#define ANDROID_KABI_USE2(n, _new1, _new2)	\
	ANDROID_KABI_REPLACE(_ANROID_KABI_RESERVE(n), struct { _new1; _new2; } )

/* Replace an existing field with a new one of the same exact size */
#define ANDROID_KABI_REPLACE(_orig, _new)	\
	_ANDROID_KABI_REPLACE(_orig, _new)


#endif /* _ANDROID_KABI_H */
