/*
 * Definitions of fingerprints.
 *
 * Copyright (c) 2020-2022 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef FINGERPRINT_H_
#define FINGERPRINT_H_

#include <linux/types.h>
#include <linux/xxhash.h>
#include "stats.h"
#include "wyhash.h"

struct nova_fp_strong_ctx {};

struct nova_fp {
	union {
		u32 index;
		u32 value;
	};
};

union xxh64ret {
	struct {
		u32 high;
		u32 low;
	};
	u64 value;
};

// _Static_assert(sizeof(struct nova_fp) == 8, "Fingerprint not 8B!");
_Static_assert(sizeof(struct nova_fp) == 4, "Fingerprint not 4B!");

static inline int nova_fp_strong_ctx_init(struct nova_fp_strong_ctx *ctx) {
	return 0;
}
static inline void nova_fp_strong_ctx_free(struct nova_fp_strong_ctx *ctx) {
}

static inline int nova_fp_calc(struct nova_fp_strong_ctx *fp_ctx, const void *addr, struct nova_fp *fp)
{
	union xxh64ret ret;
	INIT_TIMING(fp_calc_time);
	NOVA_START_TIMING(fp_calc_t, fp_calc_time);
	// ret.value = xxh64((const char *)addr, 4096, 0);
	ret.value = wyhash((const char *)addr, 4096, 0, _wyp);
	fp->value = ret.low;
	NOVA_END_TIMING(fp_calc_t, fp_calc_time);
	return 0;
}

#endif // FINGERPRINT_H_