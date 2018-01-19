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

static DEFINE_SPINLOCK(cpufreq_times_lock);

struct cpufreq_times {
	unsigned long long last_time;
	unsigned int max_state;
	unsigned int last_index;
	unsigned int offset;
	u64 *time_in_state;
};

static unsigned int next_offset;
static unsigned int *cpufreq_states;

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

static ssize_t show_all_time_in_state(struct kobject *kobj,
				      struct kobj_attribute *attr, char *buf)
{
	ssize_t len = 0;
	unsigned int i, cpu, freq;
	bool found;
	u64 time;
	struct cpufreq_policy *policy;
	struct cpufreq_times *times;

	len += scnprintf(buf + len, PAGE_SIZE - len, "freq\t\t");
	for_each_possible_cpu(cpu) {
		len += scnprintf(buf + len, PAGE_SIZE - len, "cpu%u\t\t", cpu);
		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (policy->times)
			cpufreq_times_update(policy->times);
		cpufreq_cpu_put(policy);
	}

	spin_lock(&cpufreq_times_lock);
	for (i = 0; i < next_offset; i++) {
		freq = cpufreq_states[i];
		len += scnprintf(buf + len, PAGE_SIZE - len, "\n%u\t\t", freq);
		for_each_possible_cpu(cpu) {
			found = false;
			policy = cpufreq_cpu_get(cpu);
			if (policy) {
				times = policy->times;
				if (times && times->offset <= i &&
				    i < times->offset + times->max_state) {
					time = times->time_in_state[i - times->offset];
					found = true;
				}
				cpufreq_cpu_put(policy);
			}
			if (found) {
				len += scnprintf(buf + len, PAGE_SIZE - len,
						 "%lu\t\t", (unsigned long)
						 cputime64_to_clock_t(time));
			} else {
				len += scnprintf(buf + len, PAGE_SIZE - len,
						 "N/A\t\t");
			}
		}
	}
	spin_unlock(&cpufreq_times_lock);
	len += scnprintf(buf + len, PAGE_SIZE - len, "\n");
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

static struct kobj_attribute _attr_all_time_in_state = __ATTR(all_time_in_state,
		0444, show_all_time_in_state, NULL);

static int cpufreq_times_create_table(struct cpufreq_policy *policy)
{
	int ret;
	unsigned int count = 0;
	struct cpufreq_times *times;
	struct cpufreq_frequency_table *pos, *table;
	void *tmp;

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

	spin_lock(&cpufreq_times_lock);
	tmp = krealloc(cpufreq_states,
		       sizeof(cpufreq_states[0]) * (next_offset + count),
		       GFP_ATOMIC);
	if (tmp) {
		cpufreq_states = tmp;
		cpufreq_for_each_entry(pos, table) {
			cpufreq_states[next_offset + pos - table] =
				pos->frequency;
		}
		times->offset = next_offset;
		next_offset += count;
	}
	spin_unlock(&cpufreq_times_lock);
	if (!tmp) {
		kfree(times->time_in_state);
		kfree(times);
		return -ENOMEM;
	}

	policy->times = times;
#ifdef CONFIG_CPU_FREQ_STAT
	ret = sysfs_merge_group(&policy->kobj, &times_attr_group);
#else
	ret = sysfs_create_group(&policy->kobj, &times_attr_group);
#endif
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

#ifdef CONFIG_CPU_FREQ_STAT
	sysfs_unmerge_group(&policy->kobj, &times_attr_group);
#else
	sysfs_remove_group(&policy->kobj, &times_attr_group);
#endif
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
	int ret;
	unsigned int cpu;

	for_each_online_cpu(cpu)
		cpufreq_times_create_policy(cpu);

	ret = sysfs_create_file(cpufreq_global_kobject,
			&_attr_all_time_in_state.attr);
	if (ret)
		pr_warn("Cannot create sysfs file for cpufreq stats\n");

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
