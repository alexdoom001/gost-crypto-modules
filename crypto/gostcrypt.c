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

#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/ctype.h>
#include <asm/byteorder.h>
#include "gost.h"

static int gost_paramset_id = -1;
static char *gost_custom_block = NULL;

/*
 * GOST module has the following paramsets that may be set via
 * command line of insmod/modprobe if gost compiled as a module
 * or via command line of bootloader if gost compiled statically.
 *
 * - gost_paramset_id - ID of gost substitution block to use.
 *   default: GOSTCRYPT_DEFAULT_SBT_ID
 *   for more information see: enum gost_subst_block_type declaration.
 *
 * - gost_custom_block - HEX string of 256 bytes long containing custom
 *   (user-defined) substitution block. Please note, that each "number"
 *   in a string must be represented as 2bytes hex. For example 8 is 08
 *   and 15 is ff.
 *
 * If both gost_paramset_id and gost_custom_block are set, gost_paramset_id
 * considered more prioritized.
 */

#ifdef MODULE
module_param(gost_paramset_id, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gost_paramset_id, "GOST substitution block paramset ID. (default: 3)");

module_param(gost_custom_block, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gost_custom_block, "GOST substitution block");

int gost_setup_custom_block_cmdline(const char *prefix,
				    const char *str, char *out_str)
{
	printk(KERN_ERR "%s doesn't implemented!\n", __FUNCTION__);
	return -1;
}
#else /* MODULE */
static char gost_csblock_cmdline[GOST_SUBST_BLOCK_SIZE * 2 + 1];

static int __init gost_paramset_setup(char *str)
{
	int id;

	if (get_option(&str, &id))
		gost_paramset_id = id;

	return 1;
}
__setup("gost_paramset_id=", gost_paramset_setup);

static int __init gost_setup_custom_block(char *str)
{
	int ret;

	ret = gost_setup_custom_block_cmdline("gosthash", str,
					      gost_csblock_cmdline);
	if (ret < 0)
		return 0;

	gost_custom_block = gost_csblock_cmdline;
	return 1;
}
__setup("gost_custom_block=", gost_setup_custom_block);

int gost_setup_custom_block_cmdline(const char *prefix,
				    const char *str, char *out_str)
{
	size_t deflen = GOST_SUBST_BLOCK_SIZE * 2;

	if (strlen(str) != deflen) {
		printk(KERN_ERR "%s_custom_block length must be exactly "
		       "%zd bytes long\n", prefix, deflen);
		return -1;
	}

	strncpy(out_str, str, deflen);
	out_str[deflen] = '\0';
	return 0;
}

#endif /* !MODULE */
EXPORT_SYMBOL(gost_setup_custom_block_cmdline);

static unsigned hex_value(int ch)
{
        return isdigit(ch) ? ch - '0' : ((ch | 0x20) - 'a') + 10;
}

static int __fill_subst_block_line(u8 *block_line, const char *hexstr)
{
	int i, j;

	for (i = j = 0; i < 32; i += 2, j++) {
		if (!isxdigit(hexstr[i]) || !isxdigit(hexstr[i + 1]))
			return 1;

		block_line[j] = ((hex_value(hexstr[i]) << 4) |
				 hex_value(hexstr[i + 1]));
	}

	return 0;
}

/*
 * Substitution blocks from RFC 4357
 *
 *  Note: our implementation of gost 28147-89 algorithm
 *  uses S-box matrix rotated 90 degrees counterclockwise, relative to
 *  examples given in RFC.
 *
 */
static gost_subst_block_t subst_blocks[GOST_SBT_NUMBLOCKS] = {
	/* GostR3411_94_TestParamSet: Substitution blocks
	   from test examples for GOST R 34.11-94 */
	{{0X1,0XF,0XD,0X0,0X5,0X7,0XA,0X4,0X9,0X2,0X3,0XE,0X6,0XB,0X8,0XC},
	 {0XD,0XB,0X4,0X1,0X3,0XF,0X5,0X9,0X0,0XA,0XE,0X7,0X6,0X8,0X2,0XC},
	 {0X4,0XB,0XA,0X0,0X7,0X2,0X1,0XD,0X3,0X6,0X8,0X5,0X9,0XC,0XF,0XE},
	 {0X6,0XC,0X7,0X1,0X5,0XF,0XD,0X8,0X4,0XA,0X9,0XE,0X0,0X3,0XB,0X2},
	 {0X7,0XD,0XA,0X1,0X0,0X8,0X9,0XF,0XE,0X4,0X6,0XC,0XB,0X2,0X5,0X3},
	 {0X5,0X8,0X1,0XD,0XA,0X3,0X4,0X2,0XE,0XF,0XC,0X7,0X6,0X0,0X9,0XB},
	 {0XE,0XB,0X4,0XC,0X6,0XD,0XF,0XA,0X2,0X3,0X8,0X1,0X0,0X7,0X5,0X9},
	 {0X4,0XA,0X9,0X2,0XD,0X8,0X0,0XE,0X6,0XB,0X1,0XC,0X7,0XF,0X5,0X3}},

	/* GostR3411_94_CryptoProParamSet: Substitution blocks
	   for hash function 1.2.643.2.9.1.6.1 */
	{{0x1,0x3,0xA,0x9,0x5,0xB,0x4,0xF,0x8,0x6,0x7,0xE,0xD,0x0,0x2,0xC},
	 {0xD,0xE,0x4,0x1,0x7,0x0,0x5,0xA,0x3,0xC,0x8,0xF,0x6,0x2,0x9,0xB},
	 {0x7,0x6,0x2,0x4,0xD,0x9,0xF,0x0,0xA,0x1,0x5,0xB,0x8,0xE,0xC,0x3},
	 {0x7,0x6,0x4,0xB,0x9,0xC,0x2,0xA,0x1,0x8,0x0,0xE,0xF,0xD,0x3,0x5},
	 {0x4,0xA,0x7,0xC,0x0,0xF,0x2,0x8,0xE,0x1,0x6,0x5,0xD,0xB,0x9,0x3},
	 {0x7,0xF,0xC,0xE,0x9,0x4,0x1,0x0,0x3,0xB,0x5,0x2,0x6,0xA,0x8,0xD},
	 {0x5,0xF,0x4,0x0,0x2,0xD,0xB,0x9,0x1,0x7,0x6,0x3,0xC,0xE,0xA,0x8},
	 {0xA,0x4,0x5,0x6,0x8,0x1,0x3,0x7,0xD,0xC,0xE,0x0,0x9,0x2,0xB,0xF}},

	/* Gost28147_TestParamSet: Test paramset from GOST 28147 */
	{{0xC,0x6,0x5,0x2,0xB,0x0,0x9,0xD,0x3,0xE,0x7,0xA,0xF,0x4,0x1,0x8},
	 {0x9,0xB,0xC,0x0,0x3,0x6,0x7,0x5,0x4,0x8,0xE,0xF,0x1,0xA,0x2,0xD},
	 {0x8,0xF,0x6,0xB,0x1,0x9,0xC,0x5,0xD,0x3,0x7,0xA,0x0,0xE,0x2,0x4},
	 {0x3,0xE,0x5,0x9,0x6,0x8,0x0,0xD,0xA,0xB,0x7,0xC,0x2,0x1,0xF,0x4},
	 {0xE,0x9,0xB,0x2,0x5,0xF,0x7,0x1,0x0,0xD,0xC,0x6,0xA,0x4,0x3,0x8},
	 {0xD,0x8,0xE,0xC,0x7,0x3,0x9,0xA,0x1,0x5,0x2,0x4,0x6,0xF,0x0,0xB},
	 {0xC,0x9,0xF,0xE,0x8,0x1,0x3,0xA,0x2,0x7,0x4,0xD,0x6,0x0,0xB,0x5},
	 {0x4,0x2,0xF,0x5,0x9,0x1,0x0,0x8,0xE,0x3,0xB,0xC,0xD,0x7,0xA,0x6}},

	/* Gost28147_CryptoProParamSetA: 1.2.643.2.2.31.1 */
	{{0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4},
	 {0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE},
	 {0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6},
	 {0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6},
	 {0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6},
	 {0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9},
	 {0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1},
	 {0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5}},

	/* Gost28147_CryptoProParamSetB: 1.2.643.2.2.31.2 */
	{{0x0,0x4,0xB,0xE,0x8,0x3,0x7,0x1,0xA,0x2,0x9,0x6,0xF,0xD,0x5,0xC},
	 {0x5,0x2,0xA,0xB,0x9,0x1,0xC,0x3,0x7,0x4,0xD,0x0,0x6,0xF,0x8,0xE},
	 {0x8,0x3,0x2,0x6,0x4,0xD,0xE,0xB,0xC,0x1,0x7,0xF,0xA,0x0,0x9,0x5},
	 {0x2,0x7,0xC,0xF,0x9,0x5,0xA,0xB,0x1,0x4,0x0,0xD,0x6,0x8,0xE,0x3},
	 {0x7,0x5,0x0,0xD,0xB,0x6,0x1,0x2,0x3,0xA,0xC,0xF,0x4,0xE,0x9,0x8},
	 {0xE,0xC,0x0,0xA,0x9,0x2,0xD,0xB,0x7,0x5,0x8,0xF,0x3,0x6,0x1,0x4},
	 {0x0,0x1,0x2,0xA,0x4,0xD,0x5,0xC,0x9,0x7,0x3,0xF,0xB,0x8,0x6,0xE},
	 {0x8,0x4,0xB,0x1,0x3,0x5,0x0,0x9,0x2,0xE,0xA,0xC,0xD,0x6,0x7,0xF}},

	/* Gost28147_CryptoProParamSetC: 1.2.643.2.2.31.3 */
	{{0x7,0x4,0x0,0x5,0xA,0x2,0xF,0xE,0xC,0x6,0x1,0xB,0xD,0x9,0x3,0x8},
	 {0xA,0x9,0x6,0x8,0xD,0xE,0x2,0x0,0xF,0x3,0x5,0xB,0x4,0x1,0xC,0x7},
	 {0xC,0x9,0xB,0x1,0x8,0xE,0x2,0x4,0x7,0x3,0x6,0x5,0xA,0x0,0xF,0xD},
	 {0x8,0xD,0xB,0x0,0x4,0x5,0x1,0x2,0x9,0x3,0xC,0xE,0x6,0xF,0xA,0x7},
	 {0x3,0x6,0x0,0x1,0x5,0xD,0xA,0x8,0xB,0x2,0x9,0x7,0xE,0xF,0xC,0x4},
	 {0x8,0x2,0x5,0x0,0x4,0x9,0xF,0xA,0x3,0x7,0xC,0xD,0x6,0xE,0x1,0xB},
	 {0x0,0x1,0x7,0xD,0xB,0x4,0x5,0x2,0x8,0xE,0xF,0xC,0x9,0xA,0x6,0x3},
	 {0x1,0xB,0xC,0x2,0x9,0xD,0x0,0xF,0x4,0x5,0x8,0xE,0xA,0x7,0x6,0x3}},

	/* Gost28147_CryptoProParamSetD: 1.2.643.2.2.31.4 */
	{{0x1,0xA,0x6,0x8,0xF,0xB,0x0,0x4,0xC,0x3,0x5,0x9,0x7,0xD,0x2,0xE},
	 {0x3,0x0,0x6,0xF,0x1,0xE,0x9,0x2,0xD,0x8,0xC,0x4,0xB,0xA,0x5,0x7},
	 {0x8,0x0,0xF,0x3,0x2,0x5,0xE,0xB,0x1,0xA,0x4,0x7,0xC,0x9,0xD,0x6},
	 {0x0,0xC,0x8,0x9,0xD,0x2,0xA,0xB,0x7,0x3,0x6,0x5,0x4,0xE,0xF,0x1},
	 {0x1,0x5,0xE,0xC,0xA,0x7,0x0,0xD,0x6,0x2,0xB,0x4,0x9,0x3,0xF,0x8},
	 {0x1,0xC,0xB,0x0,0xF,0xE,0x6,0x5,0xA,0xD,0x4,0x8,0x9,0x3,0x7,0x2},
	 {0xB,0x6,0x3,0x4,0xC,0xF,0xE,0x2,0x7,0xD,0x8,0x0,0x5,0xA,0x9,0x1},
	 {0xF,0xC,0x2,0xA,0x6,0x4,0x5,0x0,0x7,0x9,0xE,0xD,0x1,0xB,0x8,0x3}},

	/*
	 * Two blocks at the end are used by user-defined custom substitution
	 * blocks initialized from command line or bootloader parameter.
	 * There are GostCrypt_CustomBlock and GostHash_CustomBlock.
	 */
};

/* Packed GOST S-Boxes */
static gost_sbox_t sbox[GOST_SBT_NUMBLOCKS];

/* 64 bits */
#define GOST_BLOCK_SIZE 8

/* 256 bits */
#define GOST_KEY_SIZE	32

/*
 * Initialization of GOST S-Boxes
 *
 * NOTE: use GCC >= 4.9 for Linux >= 4.4 on x86 otherwise rol32 will not be
 *       converted into single roll instruction
 */
void gost_sbox_init(gost_sbox_t *sb, enum gost_subst_block_type btype)
{
	int i, h, l;
	gost_subst_block_t *b;

	b = gost_get_subst_block(btype);
	BUG_ON(b == NULL);

	for (i = 0; i < 256; ++i) {
		h = i / 16;
		l = i % 16;

		sb->k87[i] = rol32((b->k8[h] << 4 | b->k7 [l]) << 24, 11);
		sb->k65[i] = rol32((b->k6[h] << 4 | b->k5 [l]) << 16, 11);
		sb->k43[i] = rol32((b->k4[h] << 4 | b->k3 [l]) << 8,  11);
		sb->k21[i] = rol32((b->k2[h] << 4 | b->k1 [l]),       11);
	}
}

static void __init gost_sbox_set_init(void)
{
	enum gost_subst_block_type btype;

	for (btype = GOST_SBT_FIRST; btype < GOST_SBT_LAST; ++btype)
		gost_sbox_init(sbox + btype, btype);
}

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

	BUG_ON(gost_paramset_id < 0);
	c->sbox = gost_get_sbox(gost_paramset_id);
	gost_key(c, key);
	return 0;
}

/* Part of GOST 28147 algorithm moved into separate function */
static inline u32 f(const gost_ctx_t *c, u32 x)
{
	gost_sbox_t *sbox = c->sbox;
/*
 * This should be in some arch-specific module in theory, but since it's the only
 * architecture we really care about let it be here for now
 */
#if defined(__amd64__)
	u32 h;
	asm(
		"movzbq %%al, %%r8;"
		"movzbl %%ah, %%edx;"
		"movl 3072(%2, %%r8, 4), %%ecx;"
		"sar $16, %%rax;"
		"orl 2048(%2, %%rdx, 4), %%ecx;"
		"movzbq %%al, %%r9;"
		"movzbl %%ah, %%ebx;"
		"orl 1024(%2, %%r9, 4), %%ecx;"
		"orl (%2, %%rbx, 4), %%ecx;"
		: "=c" (h)
		: "a" (x), "S" (sbox->k87)
		: "rbx", "rdx", "r8", "r9"
		);
	return h;
#else /* !defined(__amd64__) */
	return sbox->k87[x>>24 & 255] | sbox->k65[x>>16 & 255] |
	       sbox->k43[x>>8  & 255] | sbox->k21[x     & 255];
#endif
}

/* Instead of swapping halves, swap names each round */
#define direct_rounds(c, n1, n2) \
	n2 ^= f(c, n1 + c->k[0]); n1 ^= f(c, n2 + c->k[1]); \
	n2 ^= f(c, n1 + c->k[2]); n1 ^= f(c, n2 + c->k[3]); \
	n2 ^= f(c, n1 + c->k[4]); n1 ^= f(c, n2 + c->k[5]); \
	n2 ^= f(c, n1 + c->k[6]); n1 ^= f(c, n2 + c->k[7]);

#define reverse_rounds(c, n1, n2) \
	n2 ^= f(c, n1 + c->k[7]); n1 ^= f(c, n2 + c->k[6]); \
	n2 ^= f(c, n1 + c->k[5]); n1 ^= f(c, n2 + c->k[4]); \
	n2 ^= f(c, n1 + c->k[3]); n1 ^= f(c, n2 + c->k[2]); \
	n2 ^= f(c, n1 + c->k[1]); n1 ^= f(c, n2 + c->k[0]);

static void gostcrypt(const gost_ctx_t *c, const u8 *in, u8 *out)
{
	register u32 n1, n2; /* As named in the GOST */

	n1 = le32_to_cpu(*(u32*) in);
	n2 = le32_to_cpu(*(u32*) (in + 4));

	direct_rounds  (c, n1, n2);
	direct_rounds  (c, n1, n2);
	direct_rounds  (c, n1, n2);
	reverse_rounds (c, n1, n2);

	*((u32*)out) = cpu_to_le32(n2);
	*((u32*)(out + 4)) = cpu_to_le32(n1);
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

	n1 = le32_to_cpu(*(u32*) in);
	n2 = le32_to_cpu(*(u32*) (in + 4));

	direct_rounds  (c, n1, n2);
	reverse_rounds (c, n1, n2);
	reverse_rounds (c, n1, n2);
	reverse_rounds (c, n1, n2);

	*((u32*)out) = cpu_to_le32(n2);
	*((u32*)(out + 4)) = cpu_to_le32(n1);
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

/**
 * gost_get_subst_block - Get a pointer to GOST substitution block by its type.
 *
 * @type: A type ID of gost substitution block.
 * Returns a pointer to the substitution block corresponding to @type on success
 * and NULL if no block was found.
 */
gost_subst_block_t *gost_get_subst_block(enum gost_subst_block_type type)
{
	if ((type < GOST_SBT_FIRST) || (type > GOST_SBT_LAST))
		return NULL;

	return &subst_blocks[type];
}
EXPORT_SYMBOL(gost_get_subst_block);

gost_sbox_t *gost_get_sbox(enum gost_subst_block_type type)
{
	if ((type < GOST_SBT_FIRST) || (type > GOST_SBT_LAST))
		return NULL;

	return &sbox[type];
}
EXPORT_SYMBOL(gost_get_sbox);

/**
 * gost_select_subst_block - Select substitution block ID for gost or gosthash.
 * @default_type:     Identifier of substitution block type that will be used by default.
 * @custom_type:      Identifier of custom substitution block.
 *                    (i.e. GostCrypt_CustomBlock or GostHash_CustomBlock)
 * @subst_block:      A pointer to user-defined substitution block(can be NULL)
 * @out_type:         A pointer to the int variable where result ID will be saved.
 *
 * If @out_type points to a positive number, it must be a valid substitution
 * block id. The only thing function does in this case is validating.
 * If it's negative and @subst_block is not NULL, the function tries to initialize
 * custom block with id @custom_type ID from the @subst_block hexstirng.
 * Otherwise the value of @out_type is set to @default_type.
 *
 * The function returns 0 on success and negative error code on failure.
 */
int gost_select_subst_block(enum gost_subst_block_type default_type,
			    enum gost_subst_block_type custom_type,
			    const char *subst_block,
			    int *out_type)
{
	if ((*out_type) >= 0) {
		/*
		 * If *out_type is greater than 0 it should point to valid ID
		 * of substitution block. The only thing we have to do in this
		 * case is to validate the ID.
		 */
		if ((*out_type < GOST_SBT_FIRST) ||
		    (*out_type > GOST_SBT_LAST_USR)) {
			printk(KERN_ERR "Invalid GOST paramset ID %d. Possible values "
			       "is a range [%d, %d]\n", *out_type,
			       GOST_SBT_FIRST, GOST_SBT_LAST_USR);
			return -EINVAL;
		}

		return 0;
	}
	else if (subst_block) {
		/*
		 * If custom substitution block is not NULL, it means that
		 * there is a hex string of user-defined block that was
		 * sent to the kernel via module paramset or bootloader
		 * command line. We have to validate the length of the string
		 * and convert it to the gost_subst_block_t structure.
		 */

		gost_subst_block_t *b = gost_get_subst_block(custom_type);
		int ok = 0;

		BUG_ON(b == NULL);
		if (strlen(subst_block) != (GOST_SUBST_BLOCK_SIZE * 2)) {
			printk(KERN_ERR "Invalid GOST custom block length %zd "
			       "(%d was expected)\n", strlen(subst_block),
			       (GOST_SUBST_BLOCK_SIZE * 2));
			return -EINVAL;
		}

		/* Convert the string to the gost_subst_block_t structure. */
		ok  = __fill_subst_block_line(b->k8, subst_block +   0);
		ok |= __fill_subst_block_line(b->k7, subst_block +  32);
		ok |= __fill_subst_block_line(b->k6, subst_block +  64);
		ok |= __fill_subst_block_line(b->k5, subst_block +  96);
		ok |= __fill_subst_block_line(b->k4, subst_block +  128);
		ok |= __fill_subst_block_line(b->k3, subst_block +  160);
		ok |= __fill_subst_block_line(b->k2, subst_block +  192);
		ok |= __fill_subst_block_line(b->k1, subst_block +  224);
		if (ok) {
			printk(KERN_ERR "Invalid GOST custom substitution block!"
			       " The block must be a valid hex string\n");
			return -EINVAL;
		}

		gost_sbox_init(sbox + custom_type, custom_type);

		*out_type = custom_type;
	}
	else /* Otherwise use default gost substitution block ID. */
		*out_type = default_type;

	return 0;
}
EXPORT_SYMBOL(gost_select_subst_block);

#define GOST_TESTBUF_SIZE 4096
#define MAX_IVLEN 32
struct gost_test_block {
	char	*text;
	size_t	 tlen;
	char	*key;
};

struct gost_test_result {
	struct completion completion;
	int err;
};

#define GOST_TEST_NUMBLOCKS (sizeof(gost_test_blocks) / sizeof(gost_test_blocks[0]))
static struct gost_test_block gost_test_blocks[] = {
	{
		.text = "Over the Mountains Of the Moon, Down the Valley of "
		        "the Shadow, Ride, boldly ride, The shade replied - "
		        "If you seek for  Eldorado!",
		.tlen = 128,
		.key = "06a9214036b8a15b"
		       "0102030405060708",
	},
};

static void __init gost_test_complete(struct crypto_async_request *req, int err)
{
	struct gost_test_result *result = req->data;

	if (err == -EINPROGRESS)
		return;

	result->err = err;
	complete(&result->completion);
}

static int __init handle_gost_test_code(int errcode,
					struct gost_test_result *result)
{
	int ret = 0;

	switch (errcode) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		ret = wait_for_completion_interruptible(
			&result->completion);
		if (!ret)
			ret = result->err;

		break;
	default:
		ret = errcode;
	}

	return ret;
}

static int __init do_one_gost_test(struct gost_test_block *gtb,
				   struct crypto_ablkcipher *tfm,
				   u8 *enc_buf, u8 *dec_buf)
{
	int err;
	char iv[MAX_IVLEN];
	struct ablkcipher_request *req = NULL;
	struct scatterlist sg;
	struct gost_test_result result;

	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		printk(KERN_ERR "[gost test] Failed to allocate "
		       "ablkcipher request");
		goto out;
	}

	result.err = 0;
	init_completion(&result.completion);
	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					gost_test_complete, &result);
	memset(iv, 0, MAX_IVLEN);
	crypto_ablkcipher_clear_flags(tfm, ~0);
	err = crypto_ablkcipher_setkey(tfm, gtb->key, GOST_KEY_SIZE);
	if (err) {
		printk(KERN_ERR "[gost test] setkey failed for key "
		       "%s [ERR: %d]\n",
		       gtb->key, err);
		return err;
	}

	memcpy(enc_buf, gtb->text, gtb->tlen);
	sg_init_one(&sg, enc_buf, gtb->tlen);
	ablkcipher_request_set_crypt(req, &sg, &sg, gtb->tlen, iv);
	err = handle_gost_test_code(crypto_ablkcipher_encrypt(req), &result);
	if (err) {
		printk(KERN_ERR "[gost test] Encryption failed. "
		       "[ERR: %d]\n", err);
		goto out;
	}

	memcpy(dec_buf, enc_buf, gtb->tlen);
	memset(iv, 0, MAX_IVLEN);
	result.err = 0;
	init_completion(&result.completion);
	sg_init_one(&sg, dec_buf, gtb->tlen);
	ablkcipher_request_set_crypt(req, &sg, &sg, gtb->tlen, iv);
	err = handle_gost_test_code(crypto_ablkcipher_decrypt(req), &result);
	if (err) {
		printk(KERN_ERR "[gost test] Decryption failed "
		       "[ERR: %d]\n", err);
		goto out;
	}
	if (memcmp(gtb->text, dec_buf, gtb->tlen))
		err = 1;

out:
	if (req)
		ablkcipher_request_free(req);

	return err;
}

static int __init check_gost_test_params(struct gost_test_block *gtb,
					 int testnum)
{
	if (strlen(gtb->key) != GOST_KEY_SIZE) {
		printk(KERN_ERR "[gost test] Test %d: bad key length (%zd)\n",
		       testnum, strlen(gtb->key));
		return -EINVAL;
	}
	if (gtb->tlen % GOST_BLOCK_SIZE) {
		printk(KERN_ERR "[gost test] Test %d: Text length must be "
		       "a multiple of gost block size!\n", testnum);
		return -EINVAL;
	}

	return 0;
}

static int __init do_gost_test(void)
{
	enum gost_subst_block_type def_type = gost_paramset_id;
	struct crypto_ablkcipher *tfm = NULL;
	struct gost_test_block *gtb;
	u8 *enc_buf, *dec_buf;
	int err, i;

	enc_buf = dec_buf = NULL;
	gost_paramset_id = Gost28147_TestParamSet;
	err = 0;
	tfm = crypto_alloc_ablkcipher("ecb(gost)", 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		tfm = NULL;
		printk(KERN_ERR "[gost test] Failed to load transform for "
		       "\"ecb(gost)\" [ERR: %d]", err);
		goto out;
	}

	enc_buf = kzalloc(GOST_TESTBUF_SIZE, GFP_KERNEL);
	if (!enc_buf) {
		err = -ENOMEM;
		printk(KERN_ERR "[gost test] Failed to allocate %d bytes for "
		       "encryption buffer.\n", GOST_TESTBUF_SIZE);
		goto out;
	}

	dec_buf = kzalloc(GOST_TESTBUF_SIZE, GFP_KERNEL);
	if (!dec_buf) {
		err = -ENOMEM;
		printk(KERN_ERR "[gost test] Failed to allocate %d bytes for "
		       "decryption buffer.\n", GOST_TESTBUF_SIZE);
	}
	for (i = 0; i < GOST_TEST_NUMBLOCKS; i++) {
		gtb = &gost_test_blocks[i];
		err = check_gost_test_params(gtb, i);
		if (err)
			goto out;

		err = do_one_gost_test(gtb, tfm, enc_buf, dec_buf);
		if (err > 0) {
			printk(KERN_ERR " [gost test] Test %d failed on \"%s\" "
			       "with length %zd\n", i, gtb->text, gtb->tlen);
			print_hex_dump(KERN_ERR, "encryption buffer: ", DUMP_PREFIX_OFFSET,
				       16, 1, enc_buf, gtb->tlen, 0);
			printk(KERN_ERR "-----------------------------\n");
			print_hex_dump(KERN_ERR, "decryption buffer: ", DUMP_PREFIX_OFFSET,
				       16, 1, enc_buf, gtb->tlen, 0);
			err = -EINVAL;
			goto out;
		}
		if (err < 0)
			goto out;
	}

out:
	if (tfm)
		crypto_free_ablkcipher(tfm);
	if (enc_buf)
		kfree(enc_buf);
	if (dec_buf)
		kfree(dec_buf);

	gost_paramset_id = def_type;
	return err;
}

static int __init gost_mod_init(void)
{
	int ret;
	gost_subst_block_t *sb = gost_get_subst_block(GostCrypt_CustomBlock);

	BUG_ON(sb == NULL);
	memset(sb, 0, sizeof(*sb));
	ret = gost_select_subst_block(GOSTCRYPT_DEFAULT_SBT_ID,
				      GostCrypt_CustomBlock,
				      gost_custom_block,
				      &gost_paramset_id);
	if (ret)
		return ret;

	gost_sbox_set_init();

	ret = crypto_register_alg(&gost_alg);
	if (ret) {
		printk(KERN_ERR "GOST: failed to register crypto "
		       "alg [ERR: %d]\n", ret);
		return ret;
	}

	ret = do_gost_test();
	if (ret) {
		printk(KERN_ERR "[gost] Unloading gost cryptography.\n");
		goto err;
	}

	ret = gost_debugfs_init();
	if (ret)
		goto err;

	ret = gost_debugfs_gostcrypt_init(gost_paramset_id);
	if (ret) {
		gost_debugfs_fini();
		goto err;
	}

	return 0;
err:
	crypto_unregister_alg(&gost_alg);
	return ret;
}

static void __exit gost_mod_fini(void)
{
	crypto_unregister_alg(&gost_alg);
	gost_debugfs_gostcrypt_fini();
	gost_debugfs_fini();
}

module_init(gost_mod_init);
module_exit(gost_mod_fini);

/* Linux >= 3.18 uses this macro to name autoloaded modules */
#ifndef MODULE_ALIAS_CRYPTO
#define MODULE_ALIAS_CRYPTO(name)	MODULE_ALIAS(name)
#endif

MODULE_DESCRIPTION("GOST Cipher Algorithm");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_CRYPTO("gost");
