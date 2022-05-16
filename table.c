#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "multithread.h"

// #define static _Static_assert(1, "2333");

#define NOVA_TABLE_NOT_FOUND ((uint64_t)-1)

struct nova_write_para_entry {
	struct nova_write_para_base base;
	struct nova_pmm_entry *pentry;
};

static uint64_t nova_table_leaf_find(
	const struct nova_mm_table *table,
	const struct nova_pmm_entry *pentries,
	const struct nova_fp *fp)
{
	entrynr_t index = fp->value % table->entry_allocator->num_entry;
	entrynr_t base = index & ~(ENTRY_PER_REGION - 1);
	entrynr_t offset = index & (ENTRY_PER_REGION - 1);
	entrynr_t i = offset;
	do {
		index = base + i;
		if (pentries[index].flag == NOVA_LEAF_ENTRY_MAGIC)
			if (nova_fp_equal(fp, &pentries[index].fp))
				return index;
		++i;
		i &= ENTRY_PER_REGION - 1;
	} while (i != offset);
	return NOVA_TABLE_NOT_FOUND;
}

static void nova_table_leaf_delete(
	struct nova_mm_table *table,
	entrynr_t entry_index)
{
	entrynr_t entrynr = entry_index;
	nova_free_entry(table->entry_allocator, entrynr);
}

static void print(const char *addr) {
	int i;
	for (i = 0; i < 4096; ++i) {
		printk(KERN_CONT "%02x ", addr[i] & 0xff);
	}
	printk("\n");
}
static int alloc_and_fill_block(
	struct super_block *sb,
	struct nova_write_para_normal *wp)
{
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	wp->blocknr = nova_new_data_block(sb, false, ANY_CPU);
	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	memcpy_flushcache((char *)xmem, (const char *)wp->addr, 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memlock_block(sb, xmem, &irq_flags);
	// wp->refcount = wp->base.delta;
	// printk("xmem = %pK", xmem);
	return 0;
}
static int rewrite_block(
	struct super_block *sb,
	struct nova_write_para_normal *__wp)
{
	struct nova_write_para_rewrite *wp = (struct nova_write_para_rewrite *)__wp;
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	xmem = nova_blocknr_to_addr(sb, wp->normal.blocknr);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memunlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	memcpy_flushcache((char *)xmem + wp->offset, (const char *)wp->normal.addr + wp->offset, wp->len);
	nova_memlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	// wp->refcount = wp->base.delta;
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	return 0;
}

static int nova_table_leaf_insert(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct nova_fp fp = wp->base.fp;
	int retval;

	retval = get_new_block(sb,wp);
	if(retval < 0)
		return retval;
	nova_alloc_and_write_entry(
			table->entry_allocator, fp, wp->blocknr, wp->base.refcount);

	return 0;
}
#if 0
static void print_bucket_entry(
	struct nova_mm_table *table,
	const struct nova_bucket *bucket,
	size_t index)
{
	struct nova_pmm_entry *pentry =
		table->pentries + bucket->entry_p[index].entrynr;
	struct nova_mm_entry_info entry_info = entry_info_pmm_to_mm(pentry->info);
	BUG_ON(entry_info.flag != NOVA_LEAF_ENTRY_MAGIC);
	printk("index = %lu, tag = %d, indicator = %d, blocknr = %lu, fp = %llx\n",
		index, bucket->tags[index], bucket->indicators[index],
		(unsigned long)entry_info.blocknr,
		pentry->fp.value);
}
#endif

// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr) {
	INIT_TIMING(memcmp_time);
	const void *content;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	res = cmp64(content, addr);
	NOVA_END_TIMING(memcmp_t, memcmp_time);
	if (res) {
		print(content);
		printk("\n");
		print(addr);
	}
	return res;
}
static int bucket_upsert_base(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct nova_pmm_entry *pentries = table->pentries;
	uint64_t leaf_index;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	long delta = wp->base.refcount;
	unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(mem_bucket_find_time);

retry:
	BUG_ON(delta == 0);
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(table, pentries, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index != NOVA_TABLE_NOT_FOUND) {
		pentry = pentries + leaf_index;
		BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
		blocknr = le64_to_cpu(pentry->blocknr);
		if (delta > 0) {
			if (cmp_content(sb, blocknr, wp->addr)) {
				printk("Collision, just write it.");
				return get_new_block(sb, wp);
				// const void *content = nova_get_block(sb, nova_sb_blocknr_to_addr(sb, le64_to_cpu(leaf->blocknr), NOVA_BLOCK_TYPE_4K));
				// printk("First 8 bytes of existed_entry: %llx, chunk_id = %llx, fingerprint = %llx %llx %llx %llx\nFirst 8 bytes of incoming block: %llx, fingerprint = %llx %llx %llx %llx\n",
				// 	*(uint64_t *)content, leaf->blocknr, leaf->fp_strong.u64s[0], leaf->fp_strong.u64s[1], leaf->fp_strong.u64s[2], leaf->fp_strong.u64s[3],
				// 	*(uint64_t *)addr, entry->fp_strong.u64s[0], entry->fp_strong.u64s[1], entry->fp_strong.u64s[2], entry->fp_strong.u64s[3]);
			}
			wp->blocknr = blocknr;// retrieval block info
			BUG_ON(wp->base.refcount < 0);
			nova_memunlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			ret = atomic64_add_unless(&pentry->refcount, delta, 0);
			nova_memlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			rcu_read_unlock();
			if (ret == false) {
				schedule();
				goto retry;
			}
		} else {
			if (blocknr != wp->blocknr) {
				// Collision happened. Just free it.
				rcu_read_unlock();
				printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n", __func__, blocknr, wp->blocknr);
				wp->base.refcount = 0;
				return 0;
			}
			nova_memunlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			wp->base.refcount = atomic64_add_return(
				delta, &pentry->refcount);
			nova_memlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			BUG_ON(wp->base.refcount < 0);
			if (wp->base.refcount == 0) {
				// Now only we can free the entry,
				// because there are no any other deleter.
				nova_table_leaf_delete(table, leaf_index);
				return 0;
			}
		}
		nova_flush_cacheline(pentry, false);
		// printk("Block %lu has refcount %lld now\n",
		// 	wp->blocknr, wp->base.refcount);
		return 0;
	}
	// printk("Block with fp %llx not found in rhashtable %p\n",
	// 	wp->base.fp.value, rht);
	if (delta < 0) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	if(leaf_index == NOVA_TABLE_NOT_FOUND) {
		return nova_table_leaf_insert(table, wp, get_new_block);
	}
	return -ESRCH;
}
static int bucket_upsert_normal(
	struct nova_mm_table *table,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, (struct nova_write_para_normal *)wp, alloc_and_fill_block);
}
static int bucket_upsert_rewrite(
	struct nova_mm_table *table,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, (struct nova_write_para_normal *)wp, rewrite_block);
}

// refcount-- only if refcount == 1
static int bucket_upsert_decr1(
	struct nova_mm_table *table,
	struct nova_write_para_base *__wp)
{
	struct nova_pmm_entry *pentries = table->pentries;
	uint64_t leaf_index;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	struct nova_write_para_normal *wp = (struct nova_write_para_normal *)__wp;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(table, pentries, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index == NOVA_TABLE_NOT_FOUND) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	pentry = pentries + leaf_index;
	BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
	blocknr = le64_to_cpu(pentry->blocknr);
	if (blocknr != wp->blocknr) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n",
			__func__, blocknr, wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	// The entry won't be freed by others
	// because we are referencing it.
	rcu_read_unlock();
	refcount = atomic64_cmpxchg(&pentry->refcount, 1, 0);
	BUG_ON(refcount == 0);
	if (refcount == 1) {
		// printk("Before nova_table_leaf_delete");
		nova_table_leaf_delete(table, leaf_index);
		// printk("nova_table_leaf_delete return");
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

typedef int (*bucket_upsert_func)(struct nova_mm_table *, struct nova_write_para_base *);
static int nova_table_upsert(
	struct nova_mm_table* table, 
	struct nova_write_para_base *wp,
	bucket_upsert_func bucket_upsert)
{
	return bucket_upsert(table, wp);
}
// Upsert : update or insert
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_normal);
}
// Inplace 
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_rewrite);
}
// Handle edge case when inplace
int nova_table_upsert_decr1(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_decr1);
}

static void init_normal_wp_incr(struct nova_sb_info *sbi,
	struct nova_write_para_normal *wp, const void *addr)
{
	BUG_ON(nova_fp_calc(&sbi->meta_table.fp_ctx, addr, &wp->base.fp));
	wp->addr = addr;
	wp->base.refcount = 1;
}
int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	init_normal_wp_incr(sbi, wp, addr);
	ret = nova_table_upsert_normal(table, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}
int nova_fp_table_rewrite_on_insert(struct nova_mm_table *table,
	const void *addr, struct nova_write_para_rewrite *wp,
	unsigned long blocknr, size_t offset, size_t bytes)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	init_normal_wp_incr(sbi, &wp->normal, addr);
	wp->normal.blocknr = blocknr;
	wp->offset = offset;
	wp->len = bytes;
	ret = nova_table_upsert_rewrite(table, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

void nova_table_free(struct nova_mm_table *table)
{
	return;
}
void nova_table_save(struct nova_mm_table* table)
{
	return;
}

// nelem_hint: If 0 then use default
int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p\n", psb);

	table->sblock = sb;
	table->pentries = nova_blocknr_to_addr(sb, sbi->entry_table_start);
	table->entry_allocator = &sbi->meta_table.entry_allocator;

	NOVA_END_TIMING(table_init_t, table_init_time);
	
	return 0;
}

struct table_recover_para {
	struct completion entered;
	struct nova_mm_table *table;
	entrynr_t entry_start, entry_end;
};
int nova_table_recover(struct nova_mm_table *table)
{
	return 0;
}


int nova_table_stats(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct nova_mm_table *table = &meta_table->metas;
	return __nova_entry_allocator_stats(sbi, table->entry_allocator);
}
