/*
 * Deduplication entries management.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"
#include "joinable.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))

DECLARE_PER_CPU(uint8_t, stream_trust_degree_per_cpu);
DECLARE_PER_CPU(struct nova_pmm_entry *, last_new_fpentry_per_cpu);

static int entry_allocator_alloc(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		per_cpu(last_new_fpentry_per_cpu, cpu) = NULL_PENTRY;
		per_cpu(stream_trust_degree_per_cpu, cpu) =
			HINT_TRUST_DEGREE_THRESHOLD;
	}
	spin_lock_init(&allocator->lock);
	allocator->map_blocknr_to_pentry =
		nova_sbi_blocknr_to_addr(sbi, sbi->deref_table);
	return 0;
}

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	int ret = entry_allocator_alloc(sbi, allocator);
	// The first allocation will trigger a new_region request.
	allocator->entry_collision = 0 ;
	allocator->num_entry = sbi->nr_entries;
	return ret;
}

int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	BUG();
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	return;
}

struct scan_thread_data {
	struct nova_sb_info *sbi;
	struct xatable *xat;
	regionnr_t start;
	regionnr_t end;
	struct joinable_kthread t;
};
static int scan_region(struct entry_allocator *allocator, struct xatable *xat,
	void *region_start)
{
	struct nova_pmm_entry *pentry = (struct nova_pmm_entry *)region_start;
	struct nova_pmm_entry *pentry_end = pentry + REAL_ENTRY_PER_REGION;
	int16_t count = 0;
	int ret;

	for (; pentry < pentry_end; ++pentry) {
		if (nova_pmm_entry_is_free(pentry))
			continue;
		// Impossible to conflict
		// ++count;
		// ret = xa_err(xatable_store(
		// 	xat, nova_pmm_entry_blocknr(pentry), pentry, GFP_KERNEL));
		// if (ret < 0)
		// 	return ret;
		// atomic64_set(&pentry->refcount, 0);
		// TODO: A more elegant way
		// *(u64 *)(&pentry->refcount) = 0;
		
		// clear all entries (without persistence)
		pentry->blocknr = 0;
	}
	// nova_flush_buffer(region_start, REGION_SIZE, true);
	return count;
}
static int __scan_worker(struct nova_sb_info *sbi, struct xatable *xat,
	regionnr_t region_start, regionnr_t region_end)
{
	struct entry_allocator *allocator =
		&sbi->light_dedup_meta.entry_allocator;
	__le64 *blocknrs = nova_sbi_blocknr_to_addr(
		sbi, sbi->region_blocknr_start);
	regionnr_t i;
	unsigned long blocknr;
	int ret;

	for (i = region_start; i < region_end; ++i) {
		blocknr = blocknrs[i];
		ret = scan_region(allocator, xat,
			nova_sbi_blocknr_to_addr(sbi, blocknr));
		if (ret < 0)
			return ret;
		ret = xa_err(xa_store(
			&allocator->valid_entry,
			blocknr,
			xa_mk_value(ret),
			GFP_KERNEL
		));
		if (ret < 0)
			return ret;
	}
	return 0;
}
static int scan_worker(void *__para) {
	struct scan_thread_data *data = (struct scan_thread_data *)__para;
	return __scan_worker(data->sbi, data->xat, data->start, data->end);
}
static int scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	regionnr_t region_per_thread;
	unsigned long thread_num;
	struct scan_thread_data *data = NULL;
	unsigned long i;
	regionnr_t cur_start = 0;
	int ret = 0, ret2;

	if (allocator->region_num == 0)
		return 0;
	region_per_thread = ceil_div_u32(allocator->region_num, sbi->cpus);
	thread_num = ceil_div_ul(allocator->region_num, region_per_thread);
	nova_info("Scan fingerprint entry table using %lu thread(s)\n", thread_num);
	data = kmalloc(sizeof(data[0]) * thread_num, GFP_KERNEL);
	if (data == NULL) {
		ret = -ENOMEM;
		goto out0;
	}
	for (i = 0; i < thread_num; ++i) {
		data[i].sbi = sbi;
		data[i].xat = xat;
		data[i].start = cur_start;
		cur_start += region_per_thread;
		data[i].end = min_u32(cur_start, allocator->region_num);
		data[i].t.threadfn = scan_worker;
		data[i].t.data = data + i;
		ret = joinable_kthread_create(&data[i].t, "scan_worker_%lu", i);
		if (ret < 0) {
			while (i) {
				i -= 1;
				joinable_kthread_abort(&data[i].t);
			}
			goto out1;
		}
	}
	for (i = 0; i < thread_num; ++i)
		joinable_kthread_wake_up(&data[i].t);
	for (i = 0; i < thread_num; ++i) {
		ret2 = __joinable_kthread_join(&data[i].t);
		if (ret2 < 0) {
			nova_err(sb, "%s: %lu returns %d\n", __func__, i, ret2);
			ret = ret2;
		}
	}
out1:
	kfree(data);
out0:
	return ret;
}
static void scan_region_tails(struct nova_sb_info *sbi,
	struct entry_allocator *allocator, unsigned long *bm)
{
	u64 offset = nova_get_blocknr_off(sbi->region_start);
	__le64 *next;
	allocator->region_num = 0;
	do {
		set_bit(offset / PAGE_SIZE, bm);
		++allocator->region_num;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = le64_to_cpu(*next);
	} while (offset);
	allocator->last_region_tail = next;
}
static void scan_valid_entry_count_block_tails(struct nova_sb_info *sbi,
	struct entry_allocator *allocator, unsigned long *bm)
{
	unsigned long offset = nova_get_blocknr_off(
		sbi->first_counter_block_start);
	__le64 *next;
	allocator->max_region_num = 0;
	do {
		set_bit(offset / PAGE_SIZE, bm);
		allocator->max_region_num +=
			VALID_ENTRY_COUNTER_PER_BLOCK;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = *next;
	} while (offset);
	allocator->last_counter_block_tail = next;
}
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm, size_t *tot)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	// block allocation is valid
	scan_region_tails(sbi, allocator, bm);
	scan_valid_entry_count_block_tails(sbi, allocator, bm);
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	// NOTE: do not trust any entry here, i.e., 
	// 		 there is no valid entry, we rebuild by scan bm
	ret = scan_entry_table(sb, allocator, xat);
	if (ret < 0)
		goto err_out;
	*tot = rebuild_free_regions(sbi, allocator);
	return 0;
err_out:
	nova_free_entry_allocator(allocator);
	nova_err(sb, "%s return with error code %d\n", __func__, ret);
	return ret;
}

void nova_flush_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
	// TODO: Is flushing a not dirty cache line expensive?
	nova_flush_cacheline(pentry, true);
}

entrynr_t nova_alloc_entry(struct entry_allocator *allocator, struct nova_fp fp)
{
	struct light_dedup_meta *meta =
		entry_allocator_to_light_dedup_meta(allocator);
	struct nova_pmm_entry *pentries = meta->pentries;
	entrynr_t index = fp.value % (allocator->num_entry);
	entrynr_t base = index & ~(ENTRY_PER_REGION - 1);
	entrynr_t offset = index & (ENTRY_PER_REGION - 1);
	entrynr_t i = offset;
	do {
		index = base + i;
		if (nova_pmm_entry_is_free(pentries + index))
			return index;
		++i;
		i &= ENTRY_PER_REGION - 1;
	} while (i != offset);
	return REGION_FULL;
}
void nova_write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, unsigned long blocknr)
{
	struct light_dedup_meta *meta =
		entry_allocator_to_light_dedup_meta(allocator);
	struct super_block *sb = meta->sblock;
	struct nova_pmm_entry *pentries = meta->pentries;
	struct nova_pmm_entry *pentry = pentries + entrynr;
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	// BUG_ON(atomic64_read(&pentry->refcount) != 0);

	nova_memunlock_range(sb, pentry, sizeof(*pentry), &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	atomic64_set(&pentry->next_hint,
		cpu_to_le64(HINT_TRUST_DEGREE_THRESHOLD));
	BUG_ON(pentry->blocknr != 0);
	pentry->blocknr = cpu_to_le64(blocknr);
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	nova_memlock_range(sb, pentry, sizeof(*pentry), &irq_flags);
}

static inline void
nova_clear_pmm_entry_at_blocknr(struct super_block *sb, unsigned long blocknr) 
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_pmm_entry **deref_table = nova_sbi_blocknr_to_addr(sbi, sbi->deref_table);
	unsigned long flags = 0;
	nova_memunlock_range(sb, deref_table + blocknr, sizeof(struct nova_pmm_entry), &flags);
	deref_table[blocknr] = NULL;
	nova_memlock_range(sb, deref_table + blocknr, sizeof(struct nova_pmm_entry), &flags);
}
void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
	struct nova_sb_info *sbi = entry_allocator_to_sbi(allocator);

	spin_lock_bh(&allocator->lock);
	BUG_ON(atomic64_read(&pentry->refcount) != 0);
	nova_unlock_write_flush(sbi, &pentry->blocknr, 0, true);
	spin_unlock_bh(&allocator->lock);
}

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
	int cpu;
	INIT_TIMING(save_entry_allocator_time);
	NOVA_START_TIMING(save_entry_allocator_t, save_entry_allocator_time);
	for_each_possible_cpu(cpu) {
		nova_flush_entry_if_not_null(
			per_cpu(last_new_fpentry_per_cpu, cpu), false);
	}
	nova_free_entry_allocator(allocator);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	printk("collision happens %lu\n",allocator->entry_collision);
	return 0;
}
