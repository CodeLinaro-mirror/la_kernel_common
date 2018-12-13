/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSO_TYPES_H
#define __VDSO_TYPES_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/time.h>

/*
 * The definitions below are required to overcome the limitations
 * of time_t on 32 bit architectures, which overflows in 2038.
 * The new code should use the replacements based on time64_t and
 * timespec64.
 *
 * The abstraction below will be updated once the migration to
 * time64_t is complete.
 */
#ifdef CONFIG_GENERIC_VDSO_32
#define __vdso_timespec		compat_timespec
#define __vdso_timeval		compat_timeval
#else
#ifdef ENABLE_COMPAT_VDSO
#define __vdso_timespec		compat_timespec
#define __vdso_timeval		compat_timeval
#else
#define __vdso_timespec		__kernel_timespec
#define __vdso_timeval		__kernel_old_timeval
#endif /* CONFIG_COMPAT_VDSO */
#endif /* CONFIG_GENERIC_VDSO_32 */


#endif /* !__ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* __VDSO_TYPES_H */
