/*
 * Deduplication metadata table.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "joinable.h"
#include "rhashtable-ext.h"
#include "uaccess-ext.h"
#include "entry.h"

// #define static _Static_assert(1, "2333");

// static inline void
// assign_pmm_entry_to_blocknr(struct light_dedup_meta *meta,
// 	unsigned long blocknr, struct nova_pmm_entry *pentry,
// 	struct nova_write_para_normal *wp)
// {
// 	struct nova_sb_info *sbi = light_dedup_meta_to_sbi(meta);
// 	__le64 *offset = meta->entry_allocator.map_blocknr_to_pentry + blocknr;
// 	*offset = nova_get_addr_off(sbi, pentry);
// 	if (!in_the_same_cacheline(offset, wp->dirty_map_blocknr_to_pentry) &&
// 		wp->dirty_map_blocknr_to_pentry != NULL)
// 	{
// 		nova_flush_cacheline(wp->dirty_map_blocknr_to_pentry, false);
// 	}
// 	wp->dirty_map_blocknr_to_pentry = offset;
// }

// static inline void
// clear_pmm_entry_at_blocknr(struct light_dedup_meta *meta,
// 	unsigned long blocknr) 
// {
// 	struct nova_sb_info *sbi = light_dedup_meta_to_sbi(meta);
// 	__le64 *offset = meta->entry_allocator.map_blocknr_to_pentry + blocknr;
// 	BUG_ON(*offset == 0);
// 	nova_unlock_write_flush(sbi, offset, 0, false);
// }
// static inline struct nova_pmm_entry *
// blocknr_pmm_entry(struct light_dedup_meta *meta, unsigned long blocknr)
// {
// 	return nova_get_block(meta->sblock,
// 		le64_to_cpu(
// 			meta->entry_allocator.map_blocknr_to_pentry[blocknr]));
// }

// PBN to FP mapping, for fast deletion
struct nova_revmap_entry {
	// struct rb_node node;
	__le64 blocknr;
	struct nova_fp fp;
};

static inline struct nova_revmap_entry* revmap_entry_alloc(
	struct light_dedup_meta *meta)
{
	return kmem_cache_alloc(meta->revmap_entry_cache, GFP_ATOMIC);
}

static void nova_revmap_entry_free(struct light_dedup_meta *meta, void *entry)
{
	kmem_cache_free(meta->revmap_entry_cache, entry);
}

static void nova_insert_revmap_entry(struct light_dedup_meta *meta,
	struct nova_revmap_entry *entry)
{
	xa_store(&meta->revmap, entry->blocknr, entry, GFP_ATOMIC);
}

static void nova_delete_revmap_entry(struct light_dedup_meta *meta,
	struct nova_revmap_entry *entry)
{
	xa_erase(&meta->revmap, entry->blocknr);
}

static struct nova_revmap_entry *nova_search_revmap_entry(
	struct light_dedup_meta *meta, unsigned long blocknr)
{
	return xa_load(&meta->revmap, blocknr);
}

static u32 nova_rht_entry_key_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_fp *fp = (struct nova_fp *)data;
	return fp->index;
}

static u32 nova_rht_entry_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)data;
	return entry->fp.index;
}

static int nova_rht_key_entry_cmp(
	struct rhashtable_compare_arg *arg,
	const void *obj)
{
	const struct nova_fp *fp = (const struct nova_fp *)arg->key;
	struct nova_rht_entry *entry = (struct nova_rht_entry *)obj;
	// printk("%s: %llx, %llx", __func__, fp->value, entry->fp.value);
	return fp->value != entry->fp.value;
}

const struct rhashtable_params nova_rht_params = {
	.key_len = sizeof(struct nova_fp),
	.head_offset = offsetof(struct nova_rht_entry, node),
	.automatic_shrinking = true,
	.hashfn = nova_rht_entry_key_hashfn,
	.obj_hashfn = nova_rht_entry_hashfn,
	.obj_cmpfn = nova_rht_key_entry_cmp,
};

static inline struct nova_rht_entry* rht_entry_alloc(
	struct light_dedup_meta *meta)
{
	struct nova_rht_entry* entry = kmem_cache_zalloc(meta->rht_entry_cache, GFP_ATOMIC);
	// ensure that we can use the lowest 3 bits of next_hint
	BUG_ON(((u64)entry & TRUST_DEGREE_MASK) != 0);
	return entry;
}

static void nova_rht_entry_free(void *entry, void *arg)
{
	struct kmem_cache *c = (struct kmem_cache *)arg;
	kmem_cache_free(c, entry);
}

// struct pentry_free_task {
// 	struct rcu_head head;
// 	struct entry_allocator *allocator;
// 	struct nova_pmm_entry *pentry;
// };

struct rht_entry_free_task {
	struct rcu_head head;
	struct light_dedup_meta *meta;
	struct nova_rht_entry *pentry;
};

// static void __rcu_pentry_free(struct entry_allocator *allocator,
// 	struct nova_pmm_entry *pentry)
// {
// 	struct light_dedup_meta *meta =
// 		entry_allocator_to_light_dedup_meta(allocator);
// 	struct super_block *sb = meta->sblock;
// 	unsigned long blocknr = nova_pmm_entry_blocknr(pentry);
// 	BUG_ON(blocknr == 0);
// 	clear_pmm_entry_at_blocknr(meta, blocknr);
// 	nova_free_data_block(sb, blocknr);
// 	nova_free_entry(allocator, pentry);
// }

static void __rcu_rht_entry_free(struct light_dedup_meta *meta,
	struct nova_rht_entry *pentry)
{
	// struct light_dedup_meta *meta = meta;
	struct kmem_cache *rht_entry_cache = meta->rht_entry_cache;
	
	spin_lock(&meta->revmap_lock);
	nova_delete_revmap_entry(meta, nova_search_revmap_entry(meta, pentry->blocknr));
	spin_unlock(&meta->revmap_lock);

	nova_rht_entry_free(pentry, rht_entry_cache);
}

static void rcu_rht_entry_free(struct rcu_head *head)
{
	struct rht_entry_free_task *task =
		container_of(head, struct rht_entry_free_task, head);
	__rcu_rht_entry_free(task->meta, task->pentry);
	kfree(task);
}

// static inline void new_dirty_fpentry(struct nova_rht_entry *last_pentries[2],
// 	struct nova_rht_entry *pentry)
// {
// 	last_pentries[1] = last_pentries[0];
// 	last_pentries[0] = pentry;
// }

static void free_rht_entry(
	struct light_dedup_meta *meta,
	struct nova_rht_entry *pentry)
{
	struct rht_entry_free_task *task;
	// Remove the entry first to make it invisible to other threads.
	int ret = rhashtable_remove_fast(&meta->rht, &pentry->node, nova_rht_params);
	BUG_ON(ret < 0);
	// printk("Block %lu removed from rhashtable\n",
	// 	nova_pmm_entry_blocknr(entry->pentry));
	// nova_pmm_entry_mark_to_be_freed(entry->pentry);
	task = kmalloc(sizeof(struct rht_entry_free_task), GFP_ATOMIC);
	if (task) {
		task->meta = meta;
		task->pentry = pentry;
		call_rcu(&task->head, rcu_rht_entry_free);
	} else {
		BUG_ON(1);
		// printk(KERN_ERR "%s: Fail to allocate task\n", __func__);
		// synchronize_rcu();
		// __rcu_rht_entry_free(&meta->entry_allocator, entry);
	}
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
	// unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	wp->blocknr = nova_new_data_block(sb);
	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	// nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	// memcpy_flushcache((char *)xmem, wp->addr, 4096);
	memcpy_to_pmem_nocache(xmem, wp->ubuf, 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	// nova_memlock_block(sb, xmem, &irq_flags);
	return 0;
}

static int light_dedup_fill_blocks(
	struct super_block *sb,
	struct nova_write_para_continuous *wp)
{
	void *xmem;
	// unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	// nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	// memcpy_flushcache((char *)xmem, wp->addr, 4096);
	memcpy_to_pmem_nocache(xmem, wp->ubuf, wp->num * 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	// nova_memlock_block(sb, xmem, &irq_flags);
	return NO_DEDUP;
}

#if 0
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
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	return 0;
}
#endif

static void assign_entry(
	struct nova_rht_entry *entry,
	struct nova_fp fp)
{
	entry->fp = fp;
}

static int handle_new_block(
	struct light_dedup_meta *meta,
	struct nova_write_para_continuous *wp,
	int fill_blocks(struct super_block *, struct nova_write_para_continuous *))
{
	struct super_block *sb = meta->sblock;
	struct nova_rht_entry *pentry;
	struct nova_revmap_entry *rev_entry;
	struct nova_fp fp = wp->base.fp;
	int cpu;
	int64_t refcount;
	int ret;
	INIT_TIMING(time);
	INIT_TIMING(index_insert_new_entry_time);

	NOVA_START_TIMING(handle_new_blk_t, time);
	pentry = rht_entry_alloc(meta);
	if (pentry == NULL) {
		ret = -ENOMEM;
		goto fail0;
	}
	
	rev_entry = revmap_entry_alloc(meta);
	if (rev_entry == NULL) {
		ret = -ENOMEM;
		goto fail1;
	}

	ret = fill_blocks(sb, wp);
	if (ret < 0) {
		goto fail2;
	}

	light_dedup_init_entry(pentry, fp, wp->blocknr);

	// NOTE: the first chunk of the super chunk
	rev_entry->blocknr = wp->blocknr;
	rev_entry->fp = fp;
	spin_lock(&meta->revmap_lock);
	nova_insert_revmap_entry(meta, rev_entry);
	spin_unlock(&meta->revmap_lock);
	
	nova_dbgv("insert revmap entry %lu %llu\n", wp->blocknr, fp);
	
	NOVA_START_TIMING(index_insert_new_entry_t,
		index_insert_new_entry_time);
	ret = rhashtable_lookup_insert_key(&meta->rht, &fp, &pentry->node,
		nova_rht_params);
	NOVA_END_TIMING(index_insert_new_entry_t, index_insert_new_entry_time);
	if (ret < 0) {
		printk("Block %lu with fp %llx fail to insert into rhashtable "
			"with error code %d\n", wp->blocknr, fp.value, ret);
		goto fail1;
	}
	nova_dbgv("insert fp entry %llu\n", fp);

	refcount = atomic64_cmpxchg(&pentry->refcount, 0, 1);
	BUG_ON(refcount != 0);
	wp->last_accessed = pentry;

	NOVA_END_TIMING(handle_new_blk_t, time);
	return 0;

fail2:
	nova_revmap_entry_free(meta, rev_entry);
fail1:
	nova_rht_entry_free(pentry, meta->rht_entry_cache);
fail0:
	NOVA_END_TIMING(handle_new_blk_t, time);
	return ret;
}

// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr, size_t size) {
	INIT_TIMING(memcmp_time);
	const char *content;
	size_t i, j;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	// support super chunk
	for (i = 0; i < size; i += 4096) {
		for (j = 0; j < 16; ++j)
			prefetcht0(content + j * 256);
		for (j = 0; j < 16; ++j) {
			prefetcht0(content + j * 256 + 64);
			prefetcht0(content + j * 256 + 64 * 2);
			prefetcht0(content + j * 256 + 64 * 3);
		}
		res = cmp64((const uint64_t *)content, addr);
		if (res) {
			break;
		}
		addr += 4096;
		content += 4096;
	}
	NOVA_END_TIMING(memcmp_t, memcmp_time);
	if (res) {
		nova_dbg("Block [%lu, %lu) is not equal to the incoming block.\n", blocknr, blocknr + size / 4096);
		// print(content);
		// printk("\n");
		// print(addr);
		// printk("\n");
	}
	return res;
}

static int incr_ref(struct light_dedup_meta *meta,
	struct nova_write_para_continuous *wp,
	int (*fill_blocks)(struct super_block *,
		struct nova_write_para_continuous *))
{
	struct super_block *sb = meta->sblock;
	struct rhashtable *rht = &meta->rht;
	struct nova_rht_entry *pentry;
	unsigned long blocknr;
	// unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(index_lookup_time);

retry:
	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	pentry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry, pentry, and blocknr could be freed by another thread.
	if (pentry == NULL) {
		rcu_read_unlock();
		// printk("Block with fp %llx not found in rhashtable %p\n",
		// 	wp->base.fp.value, rht);
		ret = handle_new_block(meta, wp, fill_blocks);
		if (ret == -EEXIST)
			goto retry;
		else
			ret = NO_DEDUP;
		wp->base.refcount = 1;
		return ret;
	}
	
	nova_dbgv("Found block %lu with fp %llx in rhashtable %p\n",
		pentry->blocknr, wp->base.fp.value, rht);

	blocknr = pentry->blocknr;

	BUG_ON(blocknr == 0);
	if (cmp_content(sb, blocknr, wp->kbuf, wp->num << 12)) {
		rcu_read_unlock();
		wp->last_accessed = NULL;
		nova_dbg("fp:%llx rentry.fp:%llx",wp->base.fp.value, pentry->fp.value);
		printk("Collision, just write it.\n");
		wp->base.refcount = 0;
		return fill_blocks(sb, wp);
		// const void *content = nova_get_block(sb, nova_sb_blocknr_to_addr(sb, le64_to_cpu(leaf->blocknr), NOVA_BLOCK_TYPE_4K));
		// printk("First 8 bytes of existed_entry: %llx, chunk_id = %llx, fingerprint = %llx %llx %llx %llx\nFirst 8 bytes of incoming block: %llx, fingerprint = %llx %llx %llx %llx\n",
		// 	*(uint64_t *)content, leaf->blocknr, leaf->fp_strong.u64s[0], leaf->fp_strong.u64s[1], leaf->fp_strong.u64s[2], leaf->fp_strong.u64s[3],
		// 	*(uint64_t *)addr, entry->fp_strong.u64s[0], entry->fp_strong.u64s[1], entry->fp_strong.u64s[2], entry->fp_strong.u64s[3]);
	}
	
	// retrieval block info
	// wp->blocknr = blocknr;
	
	wp->ret_blocknr = blocknr;

	// nova_memunlock_range(sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	
	wp->base.refcount = atomic64_fetch_add_unless(&pentry->refcount, 1, 0);
	
	// nova_memlock_range(sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	rcu_read_unlock();
	if (wp->base.refcount == 0)
		return -EAGAIN;
	wp->base.refcount += 1;
	// new_dirty_fpentry(wp->last_ref_entries, pentry);
	wp->last_accessed = pentry;
	// printk("Block %lu (fpentry %p) has refcount %lld now\n",
	// 	blocknr, pentry, wp->base.refcount);
	return DEDUP_SUCCESS;
}

static int incr_ref_normal(struct light_dedup_meta *meta,
	struct nova_write_para_continuous *wp)
{
	return incr_ref(meta, wp, light_dedup_fill_blocks);
}

static int light_dedup_incr_ref_atomic(struct light_dedup_meta *meta, struct nova_write_para_continuous *wp)
{
	int ret;
	void *addr = wp->kbuf;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	BUG_ON(nova_fp_calc(&meta->fp_ctx, addr, wp->num << 12, &wp->base.fp));
	nova_dbgv("Fingerprint %llx @ addr %llx\n", wp->base.fp.value, addr);
	ret = incr_ref_normal(meta, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

int light_dedup_incr_ref(struct light_dedup_meta *meta, struct nova_write_para_continuous *wp)
{
	int ret;

	while (1) {
		ret = light_dedup_incr_ref_atomic(meta, wp);
		if (likely(ret != -EAGAIN))
			break;
		schedule();
	};
	return ret;
}

static void free_pentry(struct light_dedup_meta *meta,
	struct nova_rht_entry *pentry)
{
	// struct rhashtable *rht = &meta->rht;
	// INIT_TIMING(index_lookup_time);

	// rcu_read_lock();
	// NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	// entry = rhashtable_lookup(rht, &pentry->fp, nova_rht_params);
	// NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	// BUG_ON(entry == NULL);
	// BUG_ON(entry->pentry != pentry);
	// rcu_read_unlock();

	free_rht_entry(meta, pentry);
}

static int64_t decr_ref(struct light_dedup_meta *meta,
	struct nova_rht_entry *pentry)
{
	unsigned long blocknr;
	int64_t refcount;

	// blocknr = nova_pmm_entry_blocknr(pentry);
	// BUG_ON(blocknr == 0);
	// nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	refcount = atomic64_add_return(-1, &pentry->refcount);
	// nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	BUG_ON(refcount < 0);
	if (refcount == 0) {
		// Now only we can free the entry,
		// because there are no any other deleter.
		free_pentry(meta, pentry);
	}
	return refcount;
}

void light_dedup_decr_ref(struct light_dedup_meta *meta, unsigned long blocknr)
{
	struct super_block *sb = meta->sblock;
	struct rhashtable *rht = &meta->rht;
	INIT_TIMING(decr_ref_time);
	INIT_TIMING(index_lookup_time);
	struct nova_rht_entry *pentry;
	struct nova_revmap_entry *rev_entry;
	int64_t refcount;
	
	BUG_ON(blocknr == 0);
	nova_dbgv("Decrement refcount of block %lu\n", blocknr);
	spin_lock(&meta->revmap_lock);
	rev_entry = nova_search_revmap_entry(meta, blocknr);
	if (unlikely(!rev_entry)) {
		// find the valid blocknr left from `blocknr`
		for (blocknr = blocknr - 1; blocknr > 0; --blocknr) {
			rev_entry = nova_search_revmap_entry(meta, blocknr);
			if (rev_entry)
				break;
		}
	}
	spin_unlock(&meta->revmap_lock);

	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	pentry = rhashtable_lookup(rht, &rev_entry->fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);

	// We have to hold the read lock because if it is a hash collision,
	// then the entry could be freed by another thread.
	if (!pentry) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("Fingerprint %llu can not be found in the hash table.", rev_entry->fp);
		BUG_ON(1);
	}
	
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	refcount = decr_ref(meta, pentry);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);

	// The entry won't be freed by others
	// because we are referencing it.
	rcu_read_unlock();
}

// refcount-- only if refcount == 1
static int decr_ref_1(
	struct light_dedup_meta *meta,
	struct nova_write_para_normal *wp)
{
	struct rhashtable *rht = &meta->rht;
	struct nova_rht_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	INIT_TIMING(index_lookup_time);

	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	pentry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry could be freed by another thread.
	if (!pentry) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	
	blocknr = pentry->blocknr;

	BUG_ON(blocknr == 0);
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
	refcount = atomic64_cmpxchg(&pentry->refcount, 1, 0);
	BUG_ON(refcount == 0);
	rcu_read_unlock();

	if (refcount == 1) {
		free_rht_entry(meta, pentry);
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

// long light_dedup_decr_ref_1(struct light_dedup_meta *meta, const void *addr,
// 	unsigned long blocknr)
// {
// 	struct nova_write_para_normal wp;
// 	int    retval;
// 	INIT_TIMING(decr_ref_time);

// 	BUG_ON(blocknr == 0);
// 	BUG_ON(nova_fp_calc(&meta->fp_ctx, addr, &wp.base.fp));

// 	wp.addr = addr;
// 	wp.blocknr = blocknr;
// 	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
// 	retval = decr_ref_1(meta, &wp);
// 	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
// 	return retval < 0 ? retval : wp.base.refcount;
// }

int light_dedup_insert_rht_entry(struct light_dedup_meta *meta,
	struct nova_fp fp, struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = rht_entry_alloc(meta);
	int ret;
	INIT_TIMING(insert_entry_time);

	if (entry == NULL)
		return -ENOMEM;
	NOVA_START_TIMING(insert_rht_entry_t, insert_entry_time);
	assign_entry(entry, fp);
	while (1) {
		ret = rhashtable_insert_fast(&meta->rht, &entry->node,
			nova_rht_params);
		if (ret != -EBUSY)
			break;
		schedule();
	};
	if (ret < 0) {
		printk("%s: rhashtable_insert_fast returns %d\n",
			__func__, ret);
		nova_rht_entry_free(entry, meta->rht_entry_cache);
	}
	NOVA_END_TIMING(insert_rht_entry_t, insert_entry_time);
	return ret;
}

static inline void incr_stream_trust_degree(
	struct nova_write_para_continuous *wp)
{
	if (wp->stream_trust_degree < TRUST_DEGREE_MAX)
		wp->stream_trust_degree += 1;
}

static inline void decr_stream_trust_degree(
	struct nova_write_para_continuous *wp)
{
	if (wp->stream_trust_degree < TRUST_DEGREE_MIN + 2)
		wp->stream_trust_degree = TRUST_DEGREE_MIN;
	else
		wp->stream_trust_degree -= 2;
}

static inline bool hint_trustable(uint8_t trust_degree)
{
	return trust_degree >= HINT_TRUST_DEGREE_THRESHOLD;
}

// Return the original persistent hint.
static u64 __update_hint(atomic64_t *next_hint, u64 old_hint, u64 new_hint)
{
	return le64_to_cpu(atomic64_cmpxchg_relaxed(
		next_hint,
		cpu_to_le64(old_hint),
		cpu_to_le64(new_hint)));
}

static inline bool trust_degree_out_of_bound(uint8_t trust_degree)
{
	return trust_degree & (1 << TRUST_DEGREE_BITS);
}

// Return 0: Successful
// Return x (!= 0): The offset has been changed, and the new hint is x.
static u64 __incr_trust_degree(atomic64_t *next_hint, u64 addr_ori,
	uint8_t trust_degree)
{
	__le64 old_hint = cpu_to_le64(addr_ori | trust_degree);
	__le64 tmp;
	uint64_t hint;

	while (1) {
		if (trust_degree == TRUST_DEGREE_MAX)
			return 0;
		trust_degree += 1;
		hint = addr_ori | trust_degree;
		tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
			cpu_to_le64(hint));
		if (tmp == old_hint)
			return 0;
		hint = le64_to_cpu(tmp);
		if ((hint & HINT_ADDR_MASK) != addr_ori) {
			// The hinted fpentry has been changed.
			return hint;
		}
		trust_degree = hint & TRUST_DEGREE_MASK;
		old_hint = tmp;
	}
}

// Update offset to offset_new if the resulting trust degree is not trustable.
// Return 0: Successful
// Return x (!= 0): The offset has been changed, and the new hint is x.
static u64 __decr_trust_degree(atomic64_t *next_hint, u64 addr_ori,
	u64 addr_new, uint8_t trust_degree)
{
	__le64 old_hint = cpu_to_le64(addr_ori | trust_degree);
	__le64 tmp;
	uint64_t hint;

	while (1) {
		if (trust_degree < TRUST_DEGREE_MIN + 2) {
			trust_degree = TRUST_DEGREE_MIN;
		} else {
			trust_degree -= 2;
		}

		if (!hint_trustable(trust_degree)) {
			hint = addr_new | trust_degree;
		} else {
			hint = addr_ori | trust_degree;
		}

		tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
			cpu_to_le64(hint));
		if (tmp == old_hint)
			return 0;
		hint = le64_to_cpu(tmp);
		if ((hint & HINT_ADDR_MASK) != addr_ori) {
			// The hinted fpentry has been changed.
			return hint;
		}
		trust_degree = hint & TRUST_DEGREE_MASK;
		old_hint = tmp;
	}
}

static u64 incr_trust_degree(struct nova_sb_info *sbi, atomic64_t *next_hint,
	u64 addr_ori, uint8_t trust_degree)
{
	u64 ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);

	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	ret = __incr_trust_degree(next_hint, addr_ori, trust_degree);
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint), &irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return ret;
}

static inline u64 decr_trust_degree(struct nova_sb_info *sbi,
	atomic64_t *next_hint, u64 addr_ori, u64 addr_new,
	uint8_t trust_degree)
{
	u64 ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	ret = __decr_trust_degree(next_hint, addr_ori, addr_new,
		trust_degree);
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint), &irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return ret;
}

static inline void attach_blocknr(struct nova_write_para_continuous *wp,
	unsigned long blocknr)
{
	if (wp->blocknr == 0) {
		wp->blocknr = blocknr;
		wp->num = 1;
	} else {
		// we cannot attach as fp is incorporated in the block
		wp->blocknr_next = blocknr;
	}
}

static int copy_from_user_incr_ref(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	int ret;
	INIT_TIMING(copy_from_user_time);

	NOVA_START_TIMING(copy_from_user_t, copy_from_user_time);
	ret = copy_from_user(wp->kbuf, wp->ubuf, (wp->num << 12));
	NOVA_END_TIMING(copy_from_user_t, copy_from_user_time);
	if (ret)
		return -EFAULT;
	
	ret = light_dedup_incr_ref_atomic(&sbi->light_dedup_meta, wp);
	// if (ret < 0)
	// attach_blocknr(wp, wp->blocknr);
	// return 0;
	
	return ret;
}

static int handle_no_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint,
	u64 old_hint)
{
	u64 addr;
	uint8_t trust_degree;
	uint64_t hint;
	int ret = DEDUP_SUCCESS;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);

	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;
	NOVA_STATS_ADD(no_hint, 1);
	if (unlikely(wp->last_accessed == NULL))
		return ret;

	addr = wp->last_accessed;

	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	hint = __update_hint(next_hint, old_hint,
		addr | HINT_TRUST_DEGREE_THRESHOLD);

	if ((hint & HINT_ADDR_MASK) == addr) {
		trust_degree = hint & TRUST_DEGREE_MASK;
		__incr_trust_degree(next_hint, addr, trust_degree);
	}
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return ret;
}

static int handle_not_trust(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint,
	u64 addr, uint8_t trust_degree)
{
	u64 addr_new;
	int ret = DEDUP_SUCCESS;
	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;
	if (unlikely(wp->last_accessed == NULL))
		return ret;
	addr_new = wp->last_accessed;
	if (addr_new == addr) {
		NOVA_STATS_ADD(hint_not_trusted_hit, 1);
		incr_trust_degree(sbi, next_hint, addr, trust_degree);
		incr_stream_trust_degree(wp);
	} else {
		NOVA_STATS_ADD(hint_not_trusted_miss, 1);
		decr_trust_degree(sbi, next_hint, addr, addr_new,
			trust_degree);
		decr_stream_trust_degree(wp);
	}
	return ret;
}

// The caller should hold rcu_read_lock
static void handle_hint_of_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint)
{
	uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
	u64 addr = hint & HINT_ADDR_MASK;
	uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
	struct nova_rht_entry *pentry = (struct nova_rht_entry *)addr;
	unsigned long blocknr;

	// Be conservative because prefetching consumes bandwidth.
	if (wp->stream_trust_degree != TRUST_DEGREE_MAX || addr == 0 ||
			!hint_trustable(trust_degree))
		return;
	// Do not prefetch across syscall.
	if (wp->len < PAGE_SIZE * 2)
		return;
	// pentry = nova_sbi_get_block(sbi, addr);
	// if (!nova_pmm_entry_is_readable(pentry))
	// 	return;
	if (atomic64_read(&pentry->refcount) == 0)
		return;
	blocknr = pentry->blocknr;
	// nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	wp->block_prefetching = nova_sbi_blocknr_to_addr(sbi, blocknr);
	NOVA_STATS_ADD(prefetch_next, 1);
	wp->prefetched_blocknr[1] = wp->prefetched_blocknr[0];
	wp->prefetched_blocknr[0] = blocknr;
}

static inline void prefetch_next_stage_1(struct nova_write_para_continuous *wp)
{
	size_t i;
	INIT_TIMING(time);

	if (wp->block_prefetching == NULL)
		return;
	NOVA_START_TIMING(prefetch_next_stage_1_t, time);
	for (i = 0; i < 8; ++i) {
		prefetcht2(wp->block_prefetching + i * 256);
	}
	NOVA_END_TIMING(prefetch_next_stage_1_t, time);
}

static inline void prefetch_next_stage_2(struct nova_write_para_continuous *wp)
{
	size_t i;
	INIT_TIMING(time);

	if (wp->block_prefetching == NULL)
		return;
	NOVA_START_TIMING(prefetch_next_stage_2_t, time);
	for (i = 8; i < 16; ++i) {
		prefetcht2(wp->block_prefetching + i * 256);
	}
	NOVA_END_TIMING(prefetch_next_stage_2_t, time);
	wp->block_prefetching = NULL;
}

// Return whether the block is deduplicated successfully.
static int check_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_rht_entry *speculative_pentry)
{
	struct light_dedup_meta *meta = &sbi->light_dedup_meta;
	unsigned long speculative_blocknr;
	const char *speculative_addr;
	size_t i, j;
	int64_t ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(prefetch_cmp_time);
	INIT_TIMING(cmp_user_time);
	INIT_TIMING(hit_incr_ref_time);

	// To make sure that pentry will not be released while we
	// are reading its content.
	rcu_read_lock();

	if (atomic64_read(&speculative_pentry->refcount) == 0) {
		rcu_read_unlock();
		nova_warn("Refcount is 0\n");
		return 0;
	}

	speculative_blocknr = speculative_pentry->blocknr;
	BUG_ON(speculative_blocknr == 0);
	// It is guaranteed that the block will not be freed,
	// because we are holding the RCU read lock.
	speculative_addr = nova_sbi_blocknr_to_addr(sbi, speculative_blocknr);

	if (atomic64_read(&meta->thread_num) < transition_threshold) {
		handle_hint_of_hint(sbi, wp, &speculative_pentry->next_hint);
		NOVA_START_TIMING(prefetch_cmp_t, prefetch_cmp_time);
		// Prefetch with stride 256B first in case that this block have
		// not been prefetched yet.
		for (i = 0; i < PAGE_SIZE; i += 256)
			prefetcht0(speculative_addr + i);
		for (i = 0; i < PAGE_SIZE; i += 256) {
			prefetcht0(speculative_addr + i + 64);
			prefetcht0(speculative_addr + i + 64 * 2);
			prefetcht0(speculative_addr + i + 64 * 3);
		}
		NOVA_END_TIMING(prefetch_cmp_t, prefetch_cmp_time);
	} else {
		// Do not prefetch with stride 256B if there are many threads
		// reading/writing NVM
		NOVA_START_TIMING(prefetch_cmp_t, prefetch_cmp_time);
		for (i = 0; i < PAGE_SIZE; i += 64)
			prefetcht0(speculative_addr + i);
		NOVA_END_TIMING(prefetch_cmp_t, prefetch_cmp_time);
	}

	// Increase refcount speculatively
	NOVA_START_TIMING(hit_incr_ref_t, hit_incr_ref_time);
	// nova_memunlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	ret = atomic64_add_unless(&speculative_pentry->refcount, 1, 0);
	// nova_memlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	NOVA_END_TIMING(hit_incr_ref_t, hit_incr_ref_time);
	if (ret == false) {
		rcu_read_unlock();
		return 0;
	}

	// The blocknr will not be released now, because we are referencing it.
	rcu_read_unlock();

	// prefetch the pentry.next_hint
	// prefetch_next_stage_1(wp);

	NOVA_START_TIMING(cmp_user_t, cmp_user_time);
	for (j = 0; j < (wp->num << 12); j += 4096) {
		// prefetch next chunk if j is not the last chunk
		if (j != 0) {
			for (i = 0; i < PAGE_SIZE; i += 256)
				prefetcht0(speculative_addr + j + i);
			for (i = 0; i < PAGE_SIZE; i += 256) {
				prefetcht0(speculative_addr + j + i + 64);
				prefetcht0(speculative_addr + j + i + 64 * 2);
				prefetcht0(speculative_addr + j + i + 64 * 3);
			}
		}

		if (j + 4096 < (wp->num << 12)) {
			for (i = 0; i < 8; ++i) {
				prefetcht2(speculative_addr + j + 4096 + i * 256);
			}
		}
		
		ret = cmp_user_generic_const_8B_aligned(wp->ubuf + j, speculative_addr + j, PAGE_SIZE);
		if (ret) {
			break;
		}

		if (j + 4096 < (wp->num << 12)) {
			for (i = 8; i < 16; ++i) {
				prefetcht2(speculative_addr + j + 4096 + i * 256);
			}
		}
	}
	NOVA_END_TIMING(cmp_user_t, cmp_user_time);

	// prefetch the pentry.next_hint
	// prefetch_next_stage_2(wp);

	if (ret < 0) {
		decr_ref(meta, speculative_pentry);
		return -EFAULT;
	}

	if (ret != 0) {
		decr_ref(meta, speculative_pentry);
		return 0;
	}

	if (speculative_blocknr == wp->prefetched_blocknr[1] ||
			speculative_blocknr == wp->prefetched_blocknr[0]) {
		// The hit counts of prefetching is slightly underestimated
		// because there is also probability that the current hint
		// misses but the prefetched block hits.
		NOVA_STATS_ADD(prefetch_hit, 1);
	}
	// attach_blocknr(wp, speculative_blocknr);
	// new_dirty_fpentry(wp->normal.last_ref_entries, pentry);
	wp->last_accessed = speculative_pentry;
	// printk("Prediction hit! blocknr = %ld, pentry = %p\n", blocknr, pentry);
	return 1;
}

static int handle_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint)
{
	uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
	u64 addr = hint & HINT_ADDR_MASK;
	uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
	struct nova_rht_entry *speculative_pentry = (struct nova_rht_entry *)addr;
	int ret;

	if (addr == 0) {
		// Actually no hint
		return handle_no_hint(sbi, wp, next_hint, hint);
	}
	
	if (!hint_trustable(trust_degree)) {
		return handle_not_trust(sbi, wp, next_hint,
								addr, trust_degree);
	}

	ret = check_hint(sbi, wp, speculative_pentry);

	if (ret < 0)
		return ret;
	
	if (ret == 1) {
		NOVA_STATS_ADD(predict_hit, 1);
		incr_trust_degree(sbi, next_hint, addr, trust_degree);
		incr_stream_trust_degree(wp);
		wp->ret_blocknr = speculative_pentry->blocknr;
		return DEDUP_SUCCESS;
	}

	NOVA_STATS_ADD(predict_miss, 1);
	BUG_ON(ret != 0);
	
	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;

	if (unlikely(wp->last_accessed == NULL))
		return ret;

	decr_trust_degree(sbi, next_hint, addr,
					  wp->last_accessed,
					  trust_degree);
	decr_stream_trust_degree(wp);
	return NO_DEDUP;
}

static inline struct nova_rht_entry *
get_last_accessed(struct nova_write_para_continuous *wp, bool check)
{
	struct nova_rht_entry *last_pentry = wp->last_accessed;
	return last_pentry;
}

static int handle_last_accessed_pentry(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_rht_entry *pentry)
{
	if (pentry) {
		return handle_hint(sbi, wp, &pentry->next_hint);
	} else {
		return copy_from_user_incr_ref(sbi, wp);
	}
}

int light_dedup_incr_ref_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	struct nova_rht_entry *last_pentry;
	bool first = true;
	int ret = DEDUP_SUCCESS;
	INIT_TIMING(time);

	NOVA_START_TIMING(incr_ref_continuous_t, time);
	last_pentry = get_last_accessed(wp, !first);
	while (1) {
		ret = handle_last_accessed_pentry(sbi, wp, last_pentry);
		if (likely(ret != -EAGAIN))
			break;
		// nova_memlock(sbi, &irq_flags);
		schedule();
		// nova_memunlock(sbi, &irq_flags);
	}
	
	if (ret < 0)
		goto out;

	wp->ubuf += (wp->num << 12);
	wp->len -= (wp->num << 12);
	NOVA_END_TIMING(incr_ref_continuous_t, time);
out:
	return ret;
}

struct rht_save_local_arg {
	size_t cur, end;
	struct nova_entry_refcount_record *rec;
	atomic64_t *saved;
	struct nova_sb_info *sbi;
	unsigned long irq_flags;
};
struct rht_save_factory_arg {
	struct nova_sb_info *sbi;
	atomic64_t saved;
};
// static void *rht_save_local_arg_factory(void *factory_arg) {
// 	struct rht_save_factory_arg *arg =
// 		(struct rht_save_factory_arg *)factory_arg;
// 	struct nova_sb_info *sbi = arg->sbi;
// 	struct rht_save_local_arg *local_arg = kmalloc(
// 		sizeof(struct rht_save_local_arg), GFP_ATOMIC);
// 	if (local_arg == NULL)
// 		return ERR_PTR(-ENOMEM);
// 	local_arg->cur = 0;
// 	local_arg->end = 0;
// 	local_arg->rec = nova_sbi_blocknr_to_addr(
// 		sbi, sbi->entry_refcount_record_start);
// 	local_arg->saved = &arg->saved;
// 	local_arg->sbi = sbi;
// 	local_arg->irq_flags = 0;
// 	return local_arg;
// }
// static void rht_save_local_arg_recycler(void *local_arg)
// {
// 	struct rht_save_local_arg *arg =
// 		(struct rht_save_local_arg *)local_arg;
// 	memset_nt(arg->rec + arg->cur,
// 		(arg->end - arg->cur) *
// 			sizeof(struct nova_entry_refcount_record),
// 		0);
// 	kfree(arg);
// }
// static void rht_save_worker_init(void *local_arg)
// {
// 	struct rht_save_local_arg *arg =
// 		(struct rht_save_local_arg *)local_arg;
// 	nova_memunlock(arg->sbi, &arg->irq_flags);
// }
// static void rht_save_worker_finish(void *local_arg)
// {
// 	struct rht_save_local_arg *arg =
// 		(struct rht_save_local_arg *)local_arg;
// 	nova_memlock(arg->sbi, &arg->irq_flags);
// 	PERSISTENT_BARRIER();
// }
// static void rht_save_func(void *ptr, void *local_arg)
// {
// 	struct nova_rht_entry *entry = (struct nova_rht_entry *)ptr;
// 	struct rht_save_local_arg *arg =
// 		(struct rht_save_local_arg *)local_arg;
// 	// printk("%s: entry = %p, rec = %p, cur = %lu\n", __func__, entry, arg->rec, arg->cur);
// 	// TODO: Make it a list
// 	if (arg->cur == arg->end) {
// 		arg->end = atomic64_add_return(ENTRY_PER_REGION, arg->saved);
// 		arg->cur = arg->end - ENTRY_PER_REGION;
// 		// printk("New region to save, start = %lu, end = %lu\n", arg->cur, arg->end);
// 	}
// 	nova_ntstore_val(&arg->rec[arg->cur].entry_offset,
// 		cpu_to_le64(nova_get_addr_off(arg->sbi, entry->pentry)));
// 	++arg->cur;
// }
// static void rht_save(struct nova_sb_info *sbi,
// 	struct nova_recover_meta *recover_meta, struct rhashtable *rht)
// {
// 	struct rht_save_factory_arg factory_arg;
// 	uint64_t saved;
// 	INIT_TIMING(save_refcount_time);

// 	NOVA_START_TIMING(rht_save_t, save_refcount_time);
// 	atomic64_set(&factory_arg.saved, 0);
// 	factory_arg.sbi = sbi;
// 	if (rhashtable_traverse_multithread(
// 		rht, sbi->cpus, rht_save_func, rht_save_worker_init,
// 		rht_save_worker_finish, rht_save_local_arg_factory,
// 		rht_save_local_arg_recycler, &factory_arg) < 0)
// 	{
// 		nova_warn("%s: Fail to save the fingerprint table with multithread. Fall back to single thread.", __func__);
// 		BUG(); // TODO
// 	}
// 	saved = atomic64_read(&factory_arg.saved);
// 	nova_unlock_write_flush(sbi, &recover_meta->refcount_record_num,
// 		cpu_to_le64(saved), true);
// 	printk("About %llu entries in hash table saved in NVM.", saved);
// 	NOVA_END_TIMING(rht_save_t, save_refcount_time);
// }

// struct rht_recover_para {
// 	struct light_dedup_meta *meta;
// 	entrynr_t entry_start, entry_end;
// };
// static int __rht_recover_func(struct light_dedup_meta *meta,
// 	entrynr_t entry_start, entrynr_t entry_end)
// {
// 	struct super_block *sb = meta->sblock;
// 	struct nova_sb_info *sbi = NOVA_SB(sb);
// 	struct nova_entry_refcount_record *rec = nova_sbi_blocknr_to_addr(
// 		sbi, sbi->entry_refcount_record_start);
// 	struct nova_pmm_entry *pentry;
// 	entrynr_t i;
// 	int ret = 0;
// 	// printk("entry_start = %lu, entry_end = %lu\n", (unsigned long)entry_start, (unsigned long)entry_end);
// 	for (i = entry_start; i < entry_end; ++i) {
// 		if (rec[i].entry_offset == 0)
// 			continue;
// 		pentry = (struct nova_pmm_entry *)nova_sbi_get_block(sbi,
// 			le64_to_cpu(rec[i].entry_offset));
// 		BUG_ON(nova_pmm_entry_is_free(pentry));
// 		ret = light_dedup_insert_rht_entry(meta, pentry->fp,
// 			pentry);
// 		if (ret < 0)
// 			break;
// 	}
// 	return ret;
// }
// static int rht_recover_func(void *__para)
// {
// 	struct rht_recover_para *para = (struct rht_recover_para *)__para;
// 	return __rht_recover_func(para->meta, para->entry_start,
// 		para->entry_end);
// }
// static int rht_recover(struct light_dedup_meta *meta, struct nova_sb_info *sbi,
// 	struct nova_recover_meta *recover_meta)
// {
// 	entrynr_t n = le64_to_cpu(recover_meta->refcount_record_num);
// 	unsigned long entry_per_thread_max =
// 		max_ul(1UL << 10, (n + sbi->cpus - 1) / sbi->cpus);
// 	unsigned long thread_num =
// 		(n + entry_per_thread_max - 1) / entry_per_thread_max;
// 	unsigned long i;
// 	unsigned long base;
// 	struct rht_recover_para *para;
// 	struct joinable_kthread *ts;
// 	int ret = 0;

// 	nova_info("About %lu hash table entries found.\n", (unsigned long)n);
// 	if (n == 0)
// 		return 0;
// 	nova_info("Recover fingerprint table using %lu thread(s)\n", thread_num);
// 	if (thread_num == 1)
// 		return __rht_recover_func(meta, 0, n);
// 	para = kmalloc(thread_num * sizeof(para[0]), GFP_KERNEL);
// 	if (para == NULL) {
// 		ret = -ENOMEM;
// 		goto out0;
// 	}
// 	ts = kmalloc(thread_num * sizeof(ts[0]), GFP_KERNEL);
// 	if (ts == NULL) {
// 		ret = -ENOMEM;
// 		goto out1;
// 	}
// 	base = 0;
// 	for (i = 0; i < thread_num; ++i) {
// 		para[i].meta = meta;
// 		para[i].entry_start = base;
// 		base += entry_per_thread_max;
// 		para[i].entry_end = base < n ? base : n;
// 		ts[i].threadfn = rht_recover_func;
// 		ts[i].data = para + i;
// 	}
// 	ret = joinable_kthreads_run_join_check_lt_zero(ts, thread_num,
// 		__func__);
// 	kfree(ts);
// out1:
// 	kfree(para);
// out0:
// 	return ret;
// }

static struct hlist_node *allocate_kbuf(size_t size, gfp_t flags)
{
	struct kbuf_obj *obj = kmalloc(sizeof(struct kbuf_obj), flags);
	if (obj == NULL)
		return NULL;
	obj->kbuf = kmalloc(size, flags);
	if (obj->kbuf == NULL) {
		kfree(obj);
		return NULL;
	}
	return &obj->node;
}

static void free_kbuf(struct hlist_node *node)
{
	struct kbuf_obj *obj = container_of(node, struct kbuf_obj, node);
	kfree(obj->kbuf);
	kfree(obj);
}

// nelem_hint: If 0 then use default
// entry_allocator is left for the caller to initialize
int light_dedup_meta_alloc(struct light_dedup_meta *meta,
	struct super_block *sb, size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	int ret;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(meta_alloc_t, table_init_time);
	printk("psb = %p\n", psb);
	meta->sblock = sb;
	generic_cache_init(&meta->kbuf_cache, allocate_kbuf, free_kbuf);
	ret = nova_fp_strong_ctx_init(&meta->fp_ctx);
	if (ret < 0)
		goto err_out0;

	ret = rhashtable_init_large(&meta->rht, nelem_hint, &nova_rht_params);
	if (ret < 0)
		goto err_out1;

	meta->rht_entry_cache = kmem_cache_create("rht_entry_cache",
		sizeof(struct nova_rht_entry), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (meta->rht_entry_cache == NULL) {
		ret = -ENOMEM;
		goto err_out2;
	}

	spin_lock_init(&meta->revmap_lock);
	// meta->revmap = RB_ROOT;
	xa_init(&meta->revmap);
	meta->revmap_entry_cache = kmem_cache_create("revmap_entry_cache",
		sizeof(struct nova_revmap_entry), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (meta->revmap_entry_cache == NULL) {
		ret = -ENOMEM;
		goto err_out3;
	}

	atomic64_set(&meta->thread_num, 0);
	NOVA_END_TIMING(meta_alloc_t, table_init_time);
	return 0;

err_out3:
	kmem_cache_destroy(meta->rht_entry_cache);
err_out2:
	rhashtable_free_and_destroy(&meta->rht, nova_rht_entry_free,
		meta->rht_entry_cache);
err_out1:
	nova_fp_strong_ctx_free(&meta->fp_ctx);
err_out0:
	NOVA_END_TIMING(meta_alloc_t, table_init_time);
	return ret;
}

// Free everything except entry_allocator
void light_dedup_meta_free(struct light_dedup_meta *meta)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	INIT_TIMING(table_free_time);

	generic_cache_destroy(&meta->kbuf_cache);
	nova_fp_strong_ctx_free(&meta->fp_ctx);

	NOVA_START_TIMING(rht_free_t, table_free_time);
	rhashtable_free_and_destroy_multithread(&meta->rht,
		nova_rht_entry_free, meta->rht_entry_cache, sbi->cpus);
	kmem_cache_destroy(meta->rht_entry_cache);
	NOVA_END_TIMING(rht_free_t, table_free_time);
}

int light_dedup_meta_init(struct light_dedup_meta *meta, struct super_block* sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	
	ret = light_dedup_meta_alloc(meta, sb, 0);
	if (ret < 0)
		return ret;
	
	light_dedup_init_hint_stream(sb);
	
	// We do not need allocator now
	// ret = nova_init_entry_allocator(sbi, &meta->entry_allocator);
	// if (ret < 0) {
	// 	light_dedup_meta_free(meta);
	// 	return ret;
	// }
	return 0;
}

int light_dedup_meta_restore(struct light_dedup_meta *meta,
	struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	int ret;
	INIT_TIMING(normal_recover_fp_table_time);

	ret = light_dedup_meta_alloc(meta, sb,
		le64_to_cpu(recover_meta->refcount_record_num));
	// if (ret < 0)
	// 	goto err_out0;

	// TODO: use scanning file entry result for recovery
	
	// 	ret = nova_entry_allocator_recover(sbi, &meta->entry_allocator);
	// 	if (ret < 0)
	// 		goto err_out1;

	// 	NOVA_START_TIMING(normal_recover_rht_t, normal_recover_fp_table_time);
	// 	ret = rht_recover(meta, sbi, recover_meta);
	// 	NOVA_END_TIMING(normal_recover_rht_t, normal_recover_fp_table_time);

	// 	if (ret < 0)
	// 		goto err_out2;
	// 	return 0;
	// err_out2:
	// 	nova_free_entry_allocator(&meta->entry_allocator);
	// err_out1:
	// 	light_dedup_meta_free(meta);
	// err_out0:
	return ret;
}

void light_dedup_meta_save(struct light_dedup_meta *meta)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	
	// TODO: we might store several entries of FP to PBN and 
	// PBN to FP to speedup recovery

	// rht_save(sbi, recover_meta, &meta->rht);
	// nova_save_entry_allocator(sb, &meta->entry_allocator);
	// nova_unlock_write_flush(sbi, &recover_meta->saved,
	// 	NOVA_RECOVER_META_FLAG_COMPLETE, true);

	light_dedup_meta_free(meta);
}

int nova_table_stats(struct file *file)
{
	// struct inode *inode = file_inode(file);
	// struct super_block *sb = inode->i_sb;
	// struct nova_sb_info *sbi = NOVA_SB(sb);
	// struct light_dedup_meta *meta = &sbi->light_dedup_meta;
	// return __nova_entry_allocator_stats(sbi, &meta->entry_allocator);
	// TODO:
	return 0;
}
