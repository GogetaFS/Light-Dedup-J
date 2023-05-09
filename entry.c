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
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm, size_t *tot)
{
	int ret = 0;
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

	BUG_ON(atomic64_read(&pentry->refcount) != 0);

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
