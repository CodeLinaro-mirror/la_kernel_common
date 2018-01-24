/*
 * drivers/cpufreq/cpufreq_times.c
 *
 * Copyright (C) 2018 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.*
 *
 */

#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/slab.h>

static spinlock_t cpufreq_times_lock;

struct cpufreq_times {
	unsigned long long last_time;
	unsigned int max_state;
	unsigned int last_index;
	u64 *time_in_state;
};

static int cpufreq_times_update(struct cpufreq_times *times)
{
	unsigned long long cur_time = get_jiffies_64();

	spin_lock(&cpufreq_times_lock);
	times->time_in_state[times->last_index] += cur_time - times->last_time;
	times->last_time = cur_time;
	spin_unlock(&cpufreq_times_lock);
	return 0;
}

static ssize_t show_time_in_state(struct cpufreq_policy *policy, char *buf)
{
	struct cpufreq_frequency_table *table, *pos;
	struct cpufreq_times *times = policy->times;
	ssize_t len = 0;
	int i;

	table = cpufreq_frequency_get_table(policy->cpu);
	if (!table)
		return 0;

	cpufreq_times_update(times);
	cpufreq_for_each_valid_entry(pos, table) {
		i = pos - table;
		len += sprintf(buf + len, "%u %llu\n", pos->frequency,
			       (unsigned long long)
			       jiffies_64_to_clock_t(times->time_in_state[i]));
	}
	return len;
}

cpufreq_freq_attr_ro(time_in_state);

static struct attribute *default_attrs[] = {
	&time_in_state.attr,
	NULL
};
static struct attribute_group times_attr_group = {
	.attrs = default_attrs,
	.name = "stats"
};

static int cpufreq_times_create_table(struct cpufreq_policy *policy)
{
	int ret;
	unsigned int count = 0;
	struct cpufreq_times *times;
	struct cpufreq_frequency_table *pos, *table;

	if (policy->times)
		return -EEXIST;

	table = cpufreq_frequency_get_table(policy->cpu);
	if (unlikely(!table))
		return 0;

	times = kzalloc(sizeof(*times), GFP_KERNEL);
	if (times == NULL)
		return -ENOMEM;

	cpufreq_for_each_entry(pos, table)
		count++;

	times->time_in_state = kcalloc(count, sizeof(u64), GFP_KERNEL);
	if (!times->time_in_state) {
		kfree(times);
		return -ENOMEM;
	}
	times->last_time = get_jiffies_64();
	times->last_index =
		cpufreq_frequency_table_get_index(policy, policy->cur);
	times->max_state = count;

	policy->times = times;
	ret = sysfs_merge_group(&policy->kobj, &times_attr_group);
	if (!ret)
		return 0;

	/* We failed, release resources */
	policy->times = NULL;
	kfree(times->time_in_state);
	kfree(times);

	return ret;
}

void cpufreq_times_free_table(struct cpufreq_policy *policy)
{
	struct cpufreq_times *times = policy->times;

	if (!times)
		return;

	sysfs_unmerge_group(&policy->kobj, &times_attr_group);
	kfree(times->time_in_state);
	kfree(times);
	policy->times = NULL;
}

void cpufreq_times_create_policy(unsigned int cpu)
{
	struct cpufreq_policy *policy;

	policy = cpufreq_cpu_get(cpu);
	if (!policy)
		return;

	cpufreq_times_create_table(policy);
	cpufreq_cpu_put(policy);
}

void cpufreq_times_record_transition(struct cpufreq_policy *policy,
				     struct cpufreq_freqs *freq)
{
	int index;
	struct cpufreq_times *times = policy->times;

	if (!times)
		return;

	index = cpufreq_frequency_table_get_index(policy, freq->new);
	if (index < 0)
		return;

	cpufreq_times_update(times);
	times->last_index = index;
}

static int __init cpufreq_times_init(void)
{
	unsigned int cpu;

	spin_lock_init(&cpufreq_times_lock);
	for_each_online_cpu(cpu)
		cpufreq_times_create_policy(cpu);

	return 0;
}

static void __exit cpufreq_times_exit(void)
{
	unsigned int cpu;
	struct cpufreq_policy *policy;

	for_each_online_cpu(cpu) {
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		cpufreq_times_free_table(policy);
		cpufreq_cpu_put(policy);
	}
}

module_init(cpufreq_times_init);
module_exit(cpufreq_times_exit);
