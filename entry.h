#ifndef __NOVA_ENTRY_H
#define __NOVA_ENTRY_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include "fingerprint.h"
#include "xatable.h"
#include "queue.h"

#define REGION_FULL ((entrynr_t)-1)
#define NULL_PENTRY NULL

struct nova_sb_info;

typedef uint64_t entrynr_t;
typedef uint32_t regionnr_t;

struct nova_pmm_entry {
	struct nova_fp fp;	// TODO: cpu_to_le64?
	__le64 blocknr;
	atomic64_t refcount;
	// Lowest 3 bits are trust degree: [-4, 3]
	// For each result matching the hint, the trust degree += 1
	// For each result mismatching the hint, the trust degree -= 1
	// If the trust degree < 0, then the hint is not taken.
	atomic64_t next_hint;
};
_Static_assert(sizeof(atomic64_t) == 8, "atomic64_t not 8B!");
#define TRUST_DEGREE_BITS 3
#define TRUST_DEGREE_MASK ((1 << TRUST_DEGREE_BITS) - 1)
#define TRUST_DEGREE_MAX ((1 << (TRUST_DEGREE_BITS - 1)) - 1)
#define TRUST_DEGREE_MIN (1 << (TRUST_DEGREE_BITS - 1))

#define REGION_SIZE 256
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))
#define REAL_ENTRY_PER_REGION \
	((REGION_SIZE - sizeof(__le64)) / sizeof(struct nova_pmm_entry))


struct entry_allocator {
	unsigned long num_entry;
	unsigned long entry_collision;
  spinlock_t lock;
};
#define VALID_ENTRY_COUNTER_PER_BLOCK \
	((PAGE_SIZE - sizeof(__le64)) / sizeof(uint16_t))

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm, size_t *tot);

static inline void nova_flush_entry_if_not_null(struct nova_pmm_entry *pentry,
	bool fence)
{
	if (pentry != NULL_PENTRY)
		nova_flush_cacheline(pentry, fence);
		
}

entrynr_t nova_alloc_entry(struct entry_allocator *allocator, struct nova_fp fp);
void nova_write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, unsigned long blocknr);
void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H