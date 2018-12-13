/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __VDSO_DATAPAGE_H
#define __VDSO_DATAPAGE_H

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/time.h>
#include <vdso/types.h>

#define VDSO_BASES	(CLOCK_TAI + 1)
#define VDSO_HRES	(BIT(CLOCK_REALTIME)		| \
			 BIT(CLOCK_MONOTONIC)		| \
			 BIT(CLOCK_MONOTONIC_RAW)	| \
			 BIT(CLOCK_BOOTTIME)		| \
			 BIT(CLOCK_TAI))
#define VDSO_COARSE	(BIT(CLOCK_REALTIME_COARSE)	| \
			 BIT(CLOCK_MONOTONIC_COARSE))

/*
 * There is one vdso_timestamp object in vvar for each vDSO-accelerated
 * clock_id. For high-resolution clocks, this encodes the time
 * corresponding to vdso_data.cycle_last. For coarse clocks this encodes
 * the actual time.
 *
 * To be noticed that nsec is left-shifted by vdso_data.shift.
 */
struct vdso_timestamp {
	u64 sec;
	u64 nsec;
};

/*
 * vdso_data will be accessed by 32 and 64 bit code at the same time
 * so we should be careful before modifying this structure.
 */
struct vdso_data {
	u32 seq;		/* Timebase sequence counter */

	s32 clock_mode;
	u64 cycle_last;		/* Timebase at clocksource init */
	u64 mask;		/* Clocksource mask (mono = raw) */
	u32 mult;		/* Clocksource multiplier */
	u32 shift;		/* Clocksource shift (mono = raw) */

	struct vdso_timestamp basetime[VDSO_BASES];

	s32 tz_minuteswest;	/* Timezone definitions */
	s32 tz_dsttime;
	u32 use_syscall;
	u32 __reserved;
};

#endif /* !__ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* __VDSO_DATAPAGE_H */
