/*
 * Cryptographic API.
 * Implementation of GOST R 34.11-94 hash function.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */
#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include "gost.h"

#define GOST_HASH_DIGEST_SIZE		32
#define GOST_HASH_HMAC_BLOCK_SIZE	32

typedef struct {
	long long len;
	gost_ctx_t *cipher_ctx;
	int left;
	u8 H[32];
	u8 S[32];
	u8 remainder[32];
} gost_hash_ctx_t;

static void swap_bytes(u8 *w, u8 *k)
{
	k[0]=w[0];  k[1]=w[8];   k[2]=w[16];  k[3]=w[24];
	k[4]=w[1];  k[5]=w[9];   k[6]=w[17];  k[7]=w[25];
	k[8]=w[2];  k[9]=w[10];  k[10]=w[18]; k[11]=w[26];
	k[12]=w[3]; k[13]=w[11]; k[14]=w[19]; k[15]=w[27];
	k[16]=w[4]; k[17]=w[12]; k[18]=w[20]; k[19]=w[28];
	k[20]=w[5]; k[21]=w[13]; k[22]=w[21]; k[23]=w[29];
	k[24]=w[6]; k[25]=w[14]; k[26]=w[22]; k[27]=w[30];
	k[28]=w[7]; k[29]=w[15]; k[30]=w[23]; k[31]=w[31];
}

static void circle_xor8(const u8 *w, void  *k)
{
	u32 buf[2];
	u32 *K=k;
	memcpy(buf,w,8);
	memmove(k,w+8,24);
	K[6] = buf[0] ^ K[0];
	K[7] = buf[1] ^ K[1];
}

static void transform_3(void *data)
{
	unsigned short *d=data;
	unsigned short acc;
	acc=d[0]^d[1]^d[2]^d[3]^d[12]^d[15];
	memmove(d,d+1,30);
	d[15]=acc;
}

static void transform_4(void *data)
{
	unsigned short *d=data;
	unsigned short acc1,acc2,acc3,acc4;
	acc1=(d[0]^d[1]^d[2]^d[3]^d[12]^d[15]);
	acc2=(d[0]^d[4]^d[13]^d[12]^d[15]);
	acc3=(d[2]^d[3]^d[4]^d[5]^d[14]^acc2);
	acc4=(d[2]^d[6]^d[15]^d[14]^acc2);
	memmove(d,d+4,24);
	d[12]=acc1;
	d[13]=acc2;
	d[14]=acc3;
	d[15]=acc4;
}

static int add_blocks(int n,u8 *left, const u8 *right)
{
	int i;
	int carry=0;
	int sum;
	for (i=0;i<n;i++) {
		sum=(int)left[i]+(int)right[i]+carry;
		left[i]=sum & 0xff;
		carry=sum>>8;
	}
	return carry;
}

/* Xor two sequences of bytes.
 * Len must be multiple of 4 (always 32 in GOST R 34.11-94)
 */
static void xor_blocks(void *result,const void *a,const void *b,size_t len)
{
	size_t i;
	const u32 *p=a,*q=b;
	u32 *r=result	;
	for (i=len>>2;i;i--) *(r++)=*(p++)^*(q++);
}

/*
 * 	Calculate H(i+1) = Hash(Hi,Mi)
 * 	Where H and M are 32 bytes long
 */
static void hash_step(gost_ctx_t *c, u8 *H, const u8 *M)
{
	static u8 U[32],W[32],V[32],S[32],Key[32],m[32];
	int i;
	/* Compute first key */
	memcpy(m,M,32);
	xor_blocks(W,H,m,32);
	swap_bytes(W,Key);
	/* Encrypt first 8 bytes of H with first key */
	gost_enc_with_key(c,Key,H,S);
	/* Compute second key */
	circle_xor8(H,U);
	circle_xor8(m,V);
	circle_xor8(V,V);
	xor_blocks(W,U,V,32);
	swap_bytes(W,Key);
	/* encrypt second 8 bytes of H with second key */
	gost_enc_with_key(c,Key,H+8,S+8);
	/* compute third key */
	circle_xor8(U,U);
	U[31]=~U[31]; U[29]=~U[29]; U[28]=~U[28]; U[24]=~U[24];
	U[23]=~U[23]; U[20]=~U[20]; U[18]=~U[18]; U[17]=~U[17];
	U[14]=~U[14]; U[12]=~U[12]; U[10]=~U[10]; U[ 8]=~U[ 8];
	U[ 7]=~U[ 7]; U[ 5]=~U[ 5]; U[ 3]=~U[ 3]; U[ 1]=~U[ 1];
	circle_xor8(V,V);
	circle_xor8(V,V);
	xor_blocks(W,U,V,32);
	swap_bytes(W,Key);
	/* encrypt third 8 bytes of H with third key */
	gost_enc_with_key(c,Key,H+16,S+16);
	/* Compute fourth key */
	circle_xor8(U,U);
	circle_xor8(V,V);
	circle_xor8(V,V);
	xor_blocks(W,U,V,32);
	swap_bytes(W,Key);
	/* Encrypt last 8 bytes with fourth key */
	gost_enc_with_key(c,Key,H+24,S+24);
	for (i=0;i<3;i++)
		transform_4(S);
	xor_blocks(S,S,m,32);
	transform_3(S);
	xor_blocks(S,S,H,32);
	for (i=0;i<15;i++)
		transform_4(S);
	transform_3(S);
	memcpy(H,S,32);
}

static int gost_hash_init(struct shash_desc *desc)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	memset(ctx, 0, sizeof(*ctx));
	ctx->cipher_ctx = (gost_ctx_t *)kmalloc(sizeof(gost_ctx_t), GFP_ATOMIC);
	if (!ctx->cipher_ctx)
		return -ENOMEM;
	gost_subst_block_init(ctx->cipher_ctx);
	memset(&(ctx->H), 0, 32);
	memset(&(ctx->S), 0, 32);
	ctx->len = 0L;
	ctx->left = 0;
	return 0;
}

static int gost_hash_update(struct shash_desc *desc, const u8 *block, unsigned int length)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	const u8 *curptr = block;
	const u8 *barrier = block+(length-32);/* Last byte we can safely hash*/
	gost_ctx_t *save_c = ctx->cipher_ctx;
	if (ctx->left) {
		/*There are some bytes from previous step*/
		int add_bytes = 32-ctx->left;
		if (add_bytes>length) {
			add_bytes = length;
		}
		memcpy(&(ctx->remainder[ctx->left]),block,add_bytes);
		ctx->left+=add_bytes;
		if (ctx->left != 32) {
			printk("%s() ctx->left != 32\n", __FUNCTION__);
			return -EINVAL;
		}
		curptr=block+add_bytes;
		hash_step(ctx->cipher_ctx,ctx->H,ctx->remainder);
		if (save_c != ctx->cipher_ctx) {
			printk("%s() save_c != ctx->cipher_ctx\n", __FUNCTION__);
			return -EINVAL;
		}
		add_blocks(32,ctx->S,ctx->remainder);
		if (save_c != ctx->cipher_ctx) {
			printk("%s() save_c != ctx->cipher_ctx\n", __FUNCTION__);
			return -EINVAL;
		}
		ctx->len += 32;
		ctx->left = 0;
	}
	while (curptr <= barrier) {
		hash_step(ctx->cipher_ctx,ctx->H,curptr);
		if (save_c != ctx->cipher_ctx) {
			printk("%s() save_c != ctx->cipher_ctx\n", __FUNCTION__);
			return -EINVAL;
		}
		add_blocks(32,ctx->S,curptr);
		if (save_c != ctx->cipher_ctx) {
			printk("%s() save_c != ctx->cipher_ctx\n", __FUNCTION__);
			return -EINVAL;
		}
		ctx->len += 32;
		curptr += 32;
	}
	if (curptr != block + length) {
		ctx->left = block + length - curptr;
		if (ctx->left > 32) {
			printk("%s() ctx->left > 32\n", __FUNCTION__);
			return -EINVAL;
		}
		memcpy(ctx->remainder,curptr,ctx->left);
	}
	return 0;
}

static int gost_hash_final(struct shash_desc *desc, u8 *hashval)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	u8 buf[32];
	u8 H[32];
	u8 S[32];
	long long fin_len = ctx->len;
	u8 *bptr;
	memcpy(H,ctx->H,32);
	memcpy(S,ctx->S,32);
	if (ctx->left) {
		memset(buf,0,32);
		memcpy(buf,ctx->remainder,ctx->left);
		hash_step(ctx->cipher_ctx,H,buf);
		add_blocks(32,S,buf);
		fin_len+=ctx->left;
	}
	memset(buf,0,32);
	bptr=buf;
	fin_len<<=3; /* Hash length in BITS! */
	while(fin_len>0) {
		*(bptr++)=fin_len&0xFF;
		fin_len>>=8;
	}
	hash_step(ctx->cipher_ctx,H,buf);
	hash_step(ctx->cipher_ctx,H,S);
	memcpy(hashval,H,32);
	kfree(ctx->cipher_ctx);
	return 0;
}

static struct shash_alg gost_hash_alg = {
	.digestsize	=	GOST_HASH_DIGEST_SIZE,
	.init		=	gost_hash_init,
	.update		=	gost_hash_update,
	.final		=	gost_hash_final,
	.descsize	=	sizeof(gost_hash_ctx_t),
	.base		=	{
		.cra_name	=	"gosthash",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST_HASH_HMAC_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init gost_hash_mod_init(void)
{
	return crypto_register_shash(&gost_hash_alg);
}

static void __exit gost_hash_mod_fini(void)
{
	crypto_unregister_shash(&gost_hash_alg);
}

module_init(gost_hash_mod_init);
module_exit(gost_hash_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GOST R 34.11-94 hash function");
