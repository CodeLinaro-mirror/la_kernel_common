// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic show_mem() implementation
 *
 * Copyright (C) 2008 Johannes Weiner <hannes@saeurebad.de>
 */

#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/notifier.h>
#include <linux/swap.h>

void show_mem(unsigned int filter, nodemask_t *nodemask)
{
	pg_data_t *pgdat;
	unsigned long total = 0, reserved = 0, highmem = 0;

	printk("Mem-Info:\n");
	show_free_areas(filter, nodemask);

	for_each_online_pgdat(pgdat) {
		int zoneid;

		for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {
			struct zone *zone = &pgdat->node_zones[zoneid];
			if (!populated_zone(zone))
				continue;

			total += zone->present_pages;
			reserved += zone->present_pages - zone_managed_pages(zone);

			if (is_highmem_idx(zoneid))
				highmem += zone->present_pages;
		}
	}

	printk("%lu pages RAM\n", total);
	printk("%lu pages HighMem/MovableOnly\n", highmem);
	printk("%lu pages reserved\n", reserved);
#ifdef CONFIG_CMA
	printk("%lu pages cma reserved\n", totalcma_pages);
#endif
#ifdef CONFIG_MEMORY_FAILURE
	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
#endif
}

static BLOCKING_NOTIFIER_HEAD(show_mem_notify_list);

int register_show_mem_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&show_mem_notify_list, nb);
}
EXPORT_SYMBOL_GPL(register_show_mem_notifier);

int unregister_show_mem_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&show_mem_notify_list, nb);
}
EXPORT_SYMBOL_GPL(unregister_show_mem_notifier);

void show_mem_extend(unsigned int filter, nodemask_t *nodemask,
		     enum show_mem_extend_type type)
{
	unsigned long used = 0;
	struct sysinfo si;

	pr_info("Mem-Info-Extend:\n");
	show_mem(filter, NULL);
	si_meminfo(&si);
	pr_info("MemTotal:	%8lu KB\n"
		"Buffers:	%8lu KB\n"
		"SwapCached:	%8lu KB\n",
		(si.totalram) << (PAGE_SHIFT - 10),
		(si.bufferram) << (PAGE_SHIFT - 10),
		total_swapcache_pages() << (PAGE_SHIFT - 10));

	blocking_notifier_call_chain(&show_mem_notify_list,
				     (unsigned long)type, &used);
}
