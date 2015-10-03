#ifndef KUZNECHIK_H
#define KUZNECHIK_H

#include <linux/types.h>

#ifdef __SSE__
#include <xmmintrin.h>
#endif

typedef union {
	u8  b[16];
	u64 q[2];
#ifdef __SSE__
	__m128i  o;
#endif
} u128;

typedef struct {
	u128 k[10];	/* round keys */
	u128 kd[10];	/* decryption keys */
} kuznechik_ctx_t;

#endif  /* KUZNECHIK_H */
