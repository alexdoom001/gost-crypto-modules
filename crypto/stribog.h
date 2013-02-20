#ifndef STRIBOG_H
#define STRIBOG_H

#include <linux/types.h>

typedef struct stribog_ctx {
	uint8_t N[64];
	uint8_t h[64];
	uint8_t sigma[64];
	uint8_t remainder[64];
	uint8_t rem_len;
} stribog_ctx;

#endif
