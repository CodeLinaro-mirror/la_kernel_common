// SPDX-License-Identifier: GPL-2.0
/*
 * Generic userspace implementations of gettimeofday() and similar.
 *
 * Copyright (C) 2018 ARM Limited
 * Copyright (C) 2017 Cavium, Inc.
 * Copyright (C) 2015 Mentor Graphics Corporation
 *
 */
#include <linux/compiler.h>
#include <linux/math64.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/hrtimer.h>
#include <vdso/datapage.h>
#include <vdso/helpers.h>

/*
 * The generic vDSO implementation requires that gettimeofday.h
 * provides:
 * - __arch_get_vdso_data(): to get the vdso datapage.
 * - __arch_get_hw_counter(): to get the hw counter based on the
 *   clock_mode.
 * - __arch_get_realtime_res(): to get the correct realtime res.
 * - __arch_get_coarse_res(): to get the correct coarse res.
 * - gettimeofday_fallback(): fallback for gettimeofday.
 * - clock_gettime_fallback(): fallback for clock_gettime.
 * - clock_getres_fallback(): fallback for clock_getres.
 */
#include <asm/vdso/gettimeofday.h>

#ifdef CONFIG_HAVE_HW_COUNTER
static notrace int do_hres(const struct vdso_data *vd,
			   clockid_t clk,
			   struct __vdso_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u64 cycles, last, sec, ns;
	u32 seq;

	if (vd->use_syscall)
		return -1;

	do {
		seq = vdso_read_begin(vd);
		cycles = __arch_get_hw_counter(vd->clock_mode) & vd->mask;
		ns = vdso_ts->nsec;
		last = vd->cycle_last;
		if (unlikely((s64)cycles < 0))
			return clock_gettime_fallback(clk, ts);
		if (cycles > last)
			ns += (cycles - last) * vd->mult;
		ns >>= vd->shift;
		sec = vdso_ts->sec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}
#else
static notrace int do_hres(const struct vdso_data *vd,
			   clockid_t clk,
			   struct __vdso_timespec *ts)
{
	return -1;
}
#endif

static notrace void do_coarse(const struct vdso_data *vd,
			      clockid_t clk,
			      struct __vdso_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u32 seq;

	do {
		seq = vdso_read_begin(vd);
		ts->tv_sec = vdso_ts->sec;
		ts->tv_nsec = vdso_ts->nsec;
	} while (unlikely(vdso_read_retry(vd, seq)));
}

static notrace int __cvdso_clock_gettime(clockid_t clock,
					 struct __vdso_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	u32 msk;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		goto fallback;

	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (likely(msk & VDSO_HRES)) {
		return do_hres(vd, clock, ts);
	} else if (msk & VDSO_COARSE) {
		do_coarse(vd, clock, ts);
		return 0;
	}
fallback:
	return clock_gettime_fallback(clock, ts);
}

static notrace int __cvdso_gettimeofday(struct __vdso_timeval *tv,
					struct timezone *tz)
{
	const struct vdso_data *vd = __arch_get_vdso_data();

	if (likely(tv != NULL)) {
		struct __vdso_timespec ts;

		if (do_hres(vd, CLOCK_REALTIME, &ts))
			return gettimeofday_fallback(tv, tz);

		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	}

	if (unlikely(tz != NULL)) {
		tz->tz_minuteswest = vd->tz_minuteswest;
		tz->tz_dsttime = vd->tz_dsttime;
	}

	return 0;
}

#ifdef VDSO_HAS_TIME
static notrace time_t __cvdso_time(time_t *time)
{
	u32 seq;
	time_t t;
	const struct vdso_data *vd = __arch_get_vdso_data();
	struct vdso_timestamp *vdso_ts = &vd->basetime[CLOCK_REALTIME];

repeat:
	seq = vdso_read_begin(vd);

	t = vdso_ts->sec;

	if (unlikely(vdso_read_retry(vd, seq)))
		goto repeat;

	if (unlikely(time != NULL))
		*time = t;

	return t;
}
#endif /* VDSO_HAS_TIME */

static notrace int __cvdso_clock_getres(clockid_t clock,
					struct __vdso_timespec *res)
{
	u64 ns;
	u32 msk;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		goto fallback;

	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (msk & VDSO_HRES)
		ns = __arch_get_realtime_res(clock);
	else if (msk & VDSO_COARSE)
		ns = __arch_get_coarse_res(clock);
	else
		goto fallback;

	if (res) {
		res->tv_sec = 0;
		res->tv_nsec = ns;
	}

	return 0;

fallback:
	return clock_getres_fallback(clock, res);
}
