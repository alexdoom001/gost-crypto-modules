/*
 * Cryptographic API.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * ---------------------------------------------------------------------------
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 * ---------------------------------------------------------------------------
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <asm/byteorder.h>
#include "gost.h"

/* Substitution blocks from test examples for GOST R 34.11-94*/
static gost_subst_block_t test_param_set = {
	{0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC},
	{0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC},
	{0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE},
	{0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2},
	{0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3},
	{0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB},
	{0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9},
	{0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3}
};

/* 64 bits */
#define GOST_BLOCK_SIZE 8

/* 256 bits */
#define GOST_KEY_SIZE	32

/* Initialization of gost_ctx subst blocks */
void gost_subst_block_init(gost_ctx_t *c)
{
	int i;
	register u32 x;
	const gost_subst_block_t *b = &test_param_set;

	for (i = 0; i < 256; ++i) {
		x = (b->k8[i>>4] <<4 | b->k7 [i &15])<<24;
		c->k87[i] = (x<<11 | x >> (32-11));
		x = (b->k6[i>>4] << 4 | b->k5 [i &15])<<16;
		c->k65[i] = (x<<11 | x>>(32-11));
		x = (b->k4[i>>4] <<4 | b->k3 [i &15])<<8;
		c->k43[i] = (x<<11 | x>>(32-11));
		x = b->k2[i>>4] <<4 | b->k1 [i &15];
		c->k21[i] = (x <<11 | x>> (32-11));
	}
}
EXPORT_SYMBOL(gost_subst_block_init);

/* Set 256 bit  key into context */
static void gost_key(gost_ctx_t *c, const u8 *key)
{
	c->k[0] = key[ 0] | (key[ 1]<<8) | (key[ 2]<<16) | (key[ 3]<<24);
	c->k[1] = key[ 4] | (key[ 5]<<8) | (key[ 6]<<16) | (key[ 7]<<24);
	c->k[2] = key[ 8] | (key[ 9]<<8) | (key[10]<<16) | (key[11]<<24);
	c->k[3] = key[12] | (key[13]<<8) | (key[14]<<16) | (key[15]<<24);
	c->k[4] = key[16] | (key[17]<<8) | (key[18]<<16) | (key[19]<<24);
	c->k[5] = key[20] | (key[21]<<8) | (key[22]<<16) | (key[23]<<24);
	c->k[6] = key[24] | (key[25]<<8) | (key[26]<<16) | (key[27]<<24);
	c->k[7] = key[28] | (key[29]<<8) | (key[30]<<16) | (key[31]<<24);
}

/**
 * gost_set_key - Set the GOST key.
 * @tfm:	The %crypto_tfm that is used in the context.
 * @key:	The input key.
 * @key_len:	The size of the key.
 *
 * Returns 0 on success, on failure the %CRYPTO_TFM_RES_BAD_KEY_LEN flag in tfm
 * is set.
 * &gost_ctx _must_ be the private data embedded in @tfm which is
 * retrieved with crypto_tfm_ctx().
 */
static int gost_set_key(struct crypto_tfm *tfm, const u8 *key, unsigned int key_len)
{
	gost_ctx_t *c = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;

	if (key_len != GOST_KEY_SIZE) {
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}
	gost_subst_block_init(c);
	gost_key(c, key);
	return 0;
}

/* Part of GOST 28147 algorithm moved into separate function */
static inline u32 f(const gost_ctx_t *c, u32 x)
{
	return c->k87[x>>24 & 255] | c->k65[x>>16 & 255] | c->k43[x>>8 & 255] | c->k21[x & 255];
}

static void gostcrypt(const gost_ctx_t *c, const u8 *in, u8 *out)
{
	register u32 n1, n2; /* As named in the GOST */

	n1 = in[0]|(in[1]<<8)|(in[2]<<16)|(in[3]<<24);
	n2 = in[4]|(in[5]<<8)|(in[6]<<16)|(in[7]<<24);
	/* Instead of swapping halves, swap names each round */

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	out[0] = (n2&0xff); out[1] = (n2>>8)&0xff; out[2]=(n2>>16)&0xff; out[3]=n2>>24;
	out[4] = (n1&0xff); out[5] = (n1>>8)&0xff; out[6]=(n1>>16)&0xff; out[7]=n1>>24;
}

/* encrypt a block of text */
static void gost_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const gost_ctx_t *c = crypto_tfm_ctx(tfm);
	gostcrypt(c, in, out);
}

/* Encrypts one block using specified key */
void gost_enc_with_key(gost_ctx_t *c, u8 *key, u8 *inblock, u8 *outblock)
{
	gost_key(c, key);
	gostcrypt(c, inblock, outblock);
}
EXPORT_SYMBOL(gost_enc_with_key);

/* decrypt a block of text */
static void gost_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const gost_ctx_t *c = crypto_tfm_ctx(tfm);
	register u32 n1, n2; /* As named in the GOST */

	n1 = in[0]|(in[1]<<8)|(in[2]<<16)|(in[3]<<24);
	n2 = in[4]|(in[5]<<8)|(in[6]<<16)|(in[7]<<24);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	out[0] = (n2&0xff); out[1] = (n2>>8)&0xff; out[2]=(n2>>16)&0xff; out[3]=n2>>24;
	out[4] = (n1&0xff); out[5] = (n1>>8)&0xff; out[6]=(n1>>16)&0xff; out[7]=n1>>24;
}

static struct crypto_alg gost_alg = {
	.cra_name		= "gost",
	.cra_driver_name	= "gost-generic",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= GOST_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(gost_ctx_t),
	.cra_alignmask		= 3,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(gost_alg.cra_list),
	.cra_u			= {
		.cipher = {
			.cia_min_keysize	= GOST_KEY_SIZE,
			.cia_max_keysize	= GOST_KEY_SIZE,
			.cia_setkey		= gost_set_key,
			.cia_encrypt		= gost_encrypt,
			.cia_decrypt		= gost_decrypt
		}
	}
};

static int __init gost_mod_init(void)
{
	return crypto_register_alg(&gost_alg);
}

static void __exit gost_mod_fini(void)
{
	crypto_unregister_alg(&gost_alg);
}

module_init(gost_mod_init);
module_exit(gost_mod_fini);

MODULE_DESCRIPTION("GOST Cipher Algorithm");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("gost");
