/*
 * Generic cache.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "generic_cache.h"

#include <linux/slab.h>

#define hlist_for_each_possible(name, pos, key) \
	hlist_for_each(pos, &name[hash_min(key, HASH_BITS(name))])

#define hash_for_each_safe(name, bkt, tmp, pos)			\
	for ((bkt) = 0, pos = NULL; pos == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_safe(pos, tmp, &name[bkt])

void generic_cache_init(struct generic_cache *cache,
	struct hlist_node *(*allocate)(size_t, gfp_t),
	void (*free)(struct hlist_node *))
{
	spin_lock_init(&cache->lock);
	cache->allocate = allocate;
	cache->free = free;
	cache->allocated = 0;
}

struct hlist_node *generic_cache_alloc(struct generic_cache *cache, size_t size, gfp_t flags)
{
	struct hlist_node *ret = NULL;
	spin_lock(&cache->lock);

	hlist_for_each_possible(cache->ctbl, ret, size) {
		if (ret) {
			hlist_del(ret);
			break;
		}
	}
	
	if (!ret) {
		cache->allocated += 1;
		spin_unlock(&cache->lock);
		return cache->allocate(size, flags);
	}

	spin_unlock(&cache->lock);
	return ret;
}

void generic_cache_free(struct generic_cache *cache, size_t size, struct hlist_node *node)
{
	spin_lock(&cache->lock);
	hash_add(cache->ctbl, node, size);
	spin_unlock(&cache->lock);
}

// Make sure that there is no other threads accessing it
void generic_cache_destroy(struct generic_cache *cache)
{
	size_t bkt;
	struct hlist_node *pos, *tmp;
	
	printk("Generic cache allocated %lu\n", cache->allocated);
	
	hash_for_each_safe(cache->ctbl, bkt, tmp, pos) {
		hash_del(pos);
		cache->free(pos);
	}
}
