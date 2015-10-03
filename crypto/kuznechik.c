#include <linux/bitops.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#ifdef __SSE__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#include <asm/fpu/api.h>
#else
#include <asm/i387.h>
#endif
#endif

#include "kuznechik.h"

#include "kuznechik_consts.c"

static void S(u128 *x)
{
	int i;

	for (i = 0; i < 16; ++i)
		x->b[i] = sbox[x->b[i]];
}

static void S_inv(u128 *x)
{
	int i;

	for (i = 0; i < 16; ++i)
		x->b[i] = sbox_inv[x->b[i]];
}

/* poly multiplication mod p(x) = x^8 + x^7 + x^6 + x + 1 */
static u8 mul_gf256(u8 x, u8 y)
{
	u8 z;

	for (z = 0; y != 0; y >>= 1) {
		if (y & 1)
			z ^= x;

		x = (x << 1) ^ (x & 0x80 ? 0xc3 : 0);
	}

	return z;
}

static void L(u128 *w)
{
	int i, j;
	u8 x;

	/* 16 rounds */
	for (j = 0; j < 16; j++) {
		/* An LFSR with 16 elements from GF(2^8) */
		x = w->b[15];  /* since lvec[15] = 1 */

		for (i = 14; i >= 0; i--) {
			w->b[i + 1] = w->b[i];
			x ^= mul_gf256(w->b[i], lvec[i]);
		}

		w->b[0] = x;
	}
}

static void L_inv(u128 *w)
{
	int i, j;
	u8 x;

	/* 16 rounds */
	for (j = 0; j < 16; j++) {
		x = w->b[0];

		for (i = 0; i < 15; i++) {
			w->b[i] = w->b[i + 1];
			x ^= mul_gf256(w->b[i], lvec[i]);
		}

		w->b[15] = x;
	}
}

static void xor128(const u128 *a, const u128 *b, u128 *out)
{
#ifdef __SSE__
	out->o = a->o ^ b->o;
#else
	out->q[0] = a->q[0] ^ b->q[0];
	out->q[1] = a->q[1] ^ b->q[1];
#endif
}

static u128 table_SL[16][256];
static u128 table_L_inv[16][256];
static u128 table_S_inv_L_inv[16][256];

static void kuznechik_init(void)
{
	int i, j;
	const u128 N0 = {};
	u128 x;

	for (i = 0; i < 16; i++)
		for (j = 0; j < 256; j++) {
			x = N0;
			x.b[i] = sbox[j];
			L(&x);
			table_SL[i][j] = x;

			x = N0;
			x.b[i] = j;
			L_inv(&x);
			table_L_inv[i][j] = x;

			x = N0;
			x.b[i] = sbox_inv[j];
			L_inv(&x);
			table_S_inv_L_inv[i][j] = x;
		}
}

void kuznechik_set_key(kuznechik_ctx_t *c, const u8 *key)
{
	int i;
	const u128 N0 = {};
	u128 C, x, y, z;

	memcpy(&x, key, 16);
	memcpy(&y, key + 16, 16);

	c->k[0] = x;
	c->k[1] = y;

	for (i = 1; i <= 32; i++) {
		C = N0;
		C.b[15] = i;	/* Big Endian number */
		L(&C);
		xor128(&x, &C, &z);

		S(&z);
		L(&z);
		xor128(&z, &y, &z);

		y = x;
		x = z;

		if ((i & 7) == 0) {
			c->k[(i >> 2)]     = x;
			c->k[(i >> 2) + 1] = y;
		}
	}

	/* set decryption keys */
	c->kd[0] = c->k[0];

	for (i = 1; i < 10; i++) {
		c->kd[i] = c->k[i];
		L_inv(&c->kd[i]);
	}
}

#ifdef NO_TABLES
void kuznechik_encrypt_block(const kuznechik_ctx_t *c, void *out, const void *in)
{
	int i;
	u128 *x = out;

	xor128(in, &c->k[0], x);

	for (i = 1; i <= 9; i++) {
		S(x);
		L(x);
		xor128(x, &c->k[i], x);
	}
}

void kuznechik_decrypt_block(const kuznechik_ctx_t *c, void *out, const void *in)
{
	int i;
	u128 *x = out;

	xor128(in, &c->k[9], x);

	for (i = 8; i >= 0; --i) {
		L_inv(x);
		S_inv(x);
		xor128(x, &c->k[i], x);
	}
}
#else
/* WARNING: in and out should not overlap */
static void table_it(u128 table[16][256], const u128 *in, u128 *out)
{
	int i;

	*out = table[0][in->b[0]];

	for (i = 1; i < 16; ++i)
		xor128(out, &table[i][in->b[i]], out);
}

void kuznechik_encrypt_block(const kuznechik_ctx_t *c, void *out, const void *in)
{
	int i;
	u128 *x = out, y;

	xor128(in, &c->k[0], x);

	for (i = 1; i <= 9; i++) {
		table_it(table_SL, x, &y);
		xor128(&y, &c->k[i], x);
	}
}

void kuznechik_decrypt_block(const kuznechik_ctx_t *c, void *out, const void *in)
{
	int i;
	u128 *x = out, y;

	table_it(table_L_inv, in, &y);
	xor128(&y, &c->kd[9], x);

	for (i = 8; i > 0; --i) {
		table_it(table_S_inv_L_inv, x, &y);
		xor128(&y, &c->kd[i], x);
	}

	S_inv(x);
	xor128(x, &c->kd[0], x);
}
#endif  /* !NO_TABLES */

/* Linux module interface */

#define KUZNECHIK_KEY_SIZE	32
#define KUZNECHIK_BLOCK_SIZE	16

static void sse_begin(void)
{
#ifdef __SSE__
	kernel_fpu_begin();
#endif
}

static void sse_end(void)
{
#ifdef __SSE__
	kernel_fpu_end();
#endif
}

static int kuznechik_tfm_set_key(struct crypto_tfm *tfm, const u8 *key,
				 unsigned int key_len)
{
	kuznechik_ctx_t *c = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;

	if (key_len != KUZNECHIK_KEY_SIZE) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	sse_begin();
	kuznechik_set_key(c, key);
	sse_end();

	return 0;
}

static void kuznechik_tfm_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const kuznechik_ctx_t *c = crypto_tfm_ctx(tfm);

	sse_begin();
	kuznechik_encrypt_block(c, out, in);
	sse_end();
}

static void kuznechik_tfm_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const kuznechik_ctx_t *c = crypto_tfm_ctx(tfm);

	sse_begin();
	kuznechik_decrypt_block(c, out, in);
	sse_end();
}

static struct crypto_alg kuznechik_alg = {
	.cra_name		= "kuznechik",
	.cra_driver_name	= "kuznechik-generic",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= KUZNECHIK_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(kuznechik_ctx_t),
	.cra_alignmask		= 7,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(kuznechik_alg.cra_list),
	.cra_u			= {
		.cipher = {
			.cia_min_keysize	= KUZNECHIK_KEY_SIZE,
			.cia_max_keysize	= KUZNECHIK_KEY_SIZE,
			.cia_setkey		= kuznechik_tfm_set_key,
			.cia_encrypt		= kuznechik_tfm_encrypt,
			.cia_decrypt		= kuznechik_tfm_decrypt
		}
	}
};

static int __init kuznechik_mod_init(void)
{
	kuznechik_init();

	return crypto_register_alg(&kuznechik_alg);
}

static void __exit kuznechik_mod_fini(void)
{
	crypto_unregister_alg(&kuznechik_alg);
}

module_init(kuznechik_mod_init);
module_exit(kuznechik_mod_fini);

/* Linux >= 3.18 uses this macro to name autoloaded modules */
#ifndef MODULE_ALIAS_CRYPTO
#define MODULE_ALIAS_CRYPTO(name)	MODULE_ALIAS(name)
#endif

MODULE_DESCRIPTION("GOST R 34.12-2015 Kuznyechik cipher algorithm");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_CRYPTO("kuznechik");
