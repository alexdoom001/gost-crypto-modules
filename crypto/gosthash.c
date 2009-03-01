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
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include "gost.h"

static int gosthash_paramset_id = -1;
static char *gosthash_custom_block = NULL;

/*
 * GOSTHASH module has the following paramsets that may be set via
 * command line of insmod/modprobe if gosthash compiled as a module
 * or via command line of bootloader if goshasht compiled statically.
 *
 * - gosthash_paramset_id - ID of gost substitution block to use.
 *   default: GOSTHASH_DEFAULT_SBT_ID
 *   for more information see: enum gost_subst_block_type declaration.
 *
 * - gosthash_custom_block - HEX string of 256 bytes long containing custom
 *   (user-defined) substitution block. Please note, that each "number"
 *   in a string must be represented as 2bytes hex. For example 8 is 08
 *   and 15 is ff.
 *
 * If both gosthash_paramset_id and gosthash_custom_block are set, gosthash_paramset_id
 * considered more prioritized.
 */

#ifdef MODULE
module_param(gosthash_paramset_id, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gosthash_paramset_id, "GOSTHASH substitution block paramset ID. (default: 3)");

module_param(gosthash_custom_block, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gosthash_custom_block, "GOSTHASH substitution block");
#else /* MODULE */
static char gosthash_csblock_cmdline[GOST_SUBST_BLOCK_SIZE * 2 + 1];

static int __init gosthash_paramset_setup(char *str)
{
	int id;

	if (get_option(&str, &id))
		gosthash_paramset_id = id;

	return 1;
}
__setup("gosthash_paramset_id=", gosthash_paramset_setup);

/* There should be a common function for parsin a list(an array) of unsigned chars */
static int __init gosthash_setup_custom_block(char *str)
{
	int ret;

	ret = gost_setup_custom_block_cmdline("gosthash", str,
					      gosthash_csblock_cmdline);
	if (ret < 0)
		return 0;

	gosthash_custom_block = gosthash_csblock_cmdline;
	return 1;
}
__setup("gosthash_custom_block=", gosthash_setup_custom_block);
#endif /* !MODULE */


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
	u8 U[32],W[32],V[32],S[32],Key[32];
	int i;
	/* Compute first key */
	xor_blocks(W,H,M,32);
	swap_bytes(W,Key);
	/* Encrypt first 8 bytes of H with first key */
	gost_enc_with_key(c,Key,H,S);
	/* Compute second key */
	circle_xor8(H,U);
	circle_xor8(M,V);
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
	xor_blocks(S,S,M,32);
	transform_3(S);
	xor_blocks(S,S,H,32);
	for (i=0;i<15;i++)
		transform_4(S);
	transform_3(S);
	memcpy(H,S,32);
}

static int gost_hash_init(struct shash_desc *desc, int format)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	memset(ctx, 0, sizeof(*ctx));

	BUG_ON(gosthash_paramset_id < 0);
	ctx->cipher_ctx.sbox = gost_get_sbox(gosthash_paramset_id);
	memset(&(ctx->H), 0, 32);
	memset(&(ctx->S), 0, 32);
	ctx->len = 0L;
	ctx->left = 0;
	ctx->format = format;
	return 0;
}

static int gost_hash_init_le(struct shash_desc *desc)
{
	return gost_hash_init(desc, GOSTHASH_LE);
}

static int gost_hash_init_st(struct shash_desc *desc)
{
	return gost_hash_init(desc, GOSTHASH_BE);
}

static int gost_hash_update(struct shash_desc *desc, const u8 *block, unsigned int uilen)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	const u8 *curptr = block;
	size_t length = (size_t) uilen;
	const u8 *barrier = block + (length - 32); /* Last byte we can safely hash*/

	if (ctx->left) {
		/*There are some bytes from previous step*/
		size_t add_bytes = 32-ctx->left;
		if (add_bytes>length) {
			add_bytes = length;
		}
		memcpy(&(ctx->remainder[ctx->left]),block,add_bytes);
		ctx->left+=add_bytes;
		if (ctx->left < 32) {
			pr_debug("%s() ctx->left < 32\n", __FUNCTION__);
			return 0;
		}
		curptr=block+add_bytes;
		hash_step(&ctx->cipher_ctx, ctx->H, ctx->remainder);
		add_blocks(32,ctx->S,ctx->remainder);
		ctx->len += 32;
		ctx->left = 0;
	}
	while (curptr <= barrier) {
		hash_step(&ctx->cipher_ctx, ctx->H, curptr);
		add_blocks(32,ctx->S,curptr);
		ctx->len += 32;
		curptr += 32;
	}
	if (curptr != block + length) {
		ctx->left = block + length - curptr;
		if (ctx->left > 32) {
			pr_debug("%s() ctx->left > 32\n", __FUNCTION__);
			return -EINVAL;
		}
		memcpy(ctx->remainder,curptr,ctx->left);
	}
	return 0;
}

static void *rev_memcpy (void *dst, const void *src, size_t len)
{
	const char *from;
	char *to;

	for (from = src, to = dst + len - 1; len > 0; --len, ++from, --to)
		*to = *from;

	return dst;
}

static int gost_hash_final(struct shash_desc *desc, u8 *hashval)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	u8 buf[32];
	u8 H[32];
	u8 S[32];
	unsigned long long fin_len = ctx->len;
	u8 *bptr;

	memcpy(H,ctx->H,32);
	memcpy(S,ctx->S,32);
	if (ctx->left) {
		memset(buf,0,32);
		memcpy(buf,ctx->remainder,ctx->left);
		hash_step(&ctx->cipher_ctx, H, buf);
		add_blocks(32,S,buf);
		fin_len+=ctx->left;
	}
	memset(buf,0,32);
	bptr=buf;
	fin_len<<=3; /* Hash length in BITS! */
	while(fin_len>0) {
		*(bptr++) = (u8)(fin_len&0xFF);
		fin_len>>=8;
	}
	hash_step(&ctx->cipher_ctx, H, buf);
	hash_step(&ctx->cipher_ctx, H, S);

	if (ctx->format == GOSTHASH_BE)
		rev_memcpy (hashval, H, 32);
	else
		memcpy (hashval, H, 32);

	return 0;
}

static int gost_hash_export(struct shash_desc *desc, void *out)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);
	gost_hash_ctx_t *exp = (gost_hash_ctx_t *) out;

	memcpy(exp, ctx, sizeof(gost_hash_ctx_t));

	return 0;
}

static int gost_hash_import(struct shash_desc *desc, const void *in)
{
	gost_hash_ctx_t *ctx = shash_desc_ctx(desc);

	memcpy(ctx, in, sizeof(gost_hash_ctx_t));

	return 0;
}

static struct shash_alg gost_hash_le_alg = {
	.digestsize	=	GOST_HASH_DIGEST_SIZE,
	.init		=	gost_hash_init_le,
	.update		=	gost_hash_update,
	.final		=	gost_hash_final,
	.export		=	gost_hash_export,
	.import		=	gost_hash_import,

	.descsize	=	sizeof(gost_hash_ctx_t),
	.statesize	=	sizeof(gost_hash_ctx_t),
	.base		=	{
		.cra_name	=	"gosthash",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST_HASH_HMAC_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

static struct shash_alg gost_hash_st_alg = {
	.digestsize	=	GOST_HASH_DIGEST_SIZE,
	.init		=	gost_hash_init_st,
	.update		=	gost_hash_update,
	.final		=	gost_hash_final,
	.export		=	gost_hash_export,
	.import		=	gost_hash_import,

	.descsize	=	sizeof(gost_hash_ctx_t),
	.statesize	=	sizeof(gost_hash_ctx_t),
	.base		=	{
		.cra_name	=	"gosthash-st",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	GOST_HASH_HMAC_BLOCK_SIZE,
		.cra_module	=	THIS_MODULE,
	}
};

struct gosthash_test {
	u8	*text;
	size_t	 tlen;
	u8	*result;
};

#define GOSTHASH_NUMTESTS (sizeof(gosthash_tests) / sizeof(gosthash_tests[0]))
#define GOSTHASH_TEST_BUFSIZE 4096
static struct gosthash_test gosthash_tests[] = {
	{
		.text = "Over the Mountains Of the Moon, Down the Valley of "
		        "the Shadow, Ride, boldly ride, The shade replied - "
		        "If you seek for  Eldorado!",
		.tlen = 128,
		.result = "\xe6\x34\xa8\xec\x1e\x65\x9f\x10"
		          "\x16\xa5\x72\x0a\x99\xbb\xfe\x42"
		          "\x94\x72\x7b\x8c\xf9\xcb\xee\x01"
		          "\xc8\xc6\xab\x68\xf5\x6a\x4a\xee",
	},
	{
		.text = "Each man's death diminishes me, For I am involved in mankind. "
		        "Therefore, send not to know For whom the bell tolls, It tolls for thee.",
		.tlen = 133,
		.result = "\xa0\xdd\x09\x4a\xc5\x2d\xd1\x1a"
		          "\x5d\x77\xd4\x73\x3f\x95\xd6\xda"
		          "\x4a\x03\x89\x38\xed\x19\x48\xa7"
		          "\xaf\x68\x14\x04\xdb\xd5\xdf\x7e",
	},
};

static int __init do_gosthash_test(void)
{
	enum gost_subst_block_type def_type = gosthash_paramset_id;
	struct crypto_hash *tfm = NULL;
	struct hash_desc hdesc;
	struct gosthash_test *ght;
	struct scatterlist sg;
	u8 hash[GOST_HASH_DIGEST_SIZE], *buf = NULL;
	int err = 0, i;

	gosthash_paramset_id = GostR3411_94_TestParamSet;
	tfm = crypto_alloc_hash("gosthash", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		tfm = NULL;
		printk(KERN_ERR "[gosthash test] Failed to allocate "
		       "gosthash transform. [ERR: %d]\n", err);
		goto out;
	}

	hdesc.tfm = tfm;
	buf = kmalloc(GOSTHASH_TEST_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		printk(KERN_ERR "[gosthash test] Failed to allocate "
		       "%d bytes for gosthash buffer!\n", GOSTHASH_TEST_BUFSIZE);
		goto out;
	}
	for (i = 0; i < GOSTHASH_NUMTESTS; i++) {
		ght = &gosthash_tests[i];
		err = crypto_hash_init(&hdesc);
		if (err) {
			printk(KERN_ERR "[gosthash test] Test %d: Failed to "
			       "init gost hash. [ERR: %d]\n", i, err);
			goto out;
		}

		memcpy(buf, ght->text, ght->tlen);
		sg_init_one(&sg, buf, ght->tlen);
		err = crypto_hash_update(&hdesc, &sg, ght->tlen);
		if (err) {
			printk(KERN_ERR "[gosthash test] Test %d: Failed to "
			       "update gosthash. [ERR: %d]\n", i, err);
			goto out;
		}

		err = crypto_hash_final(&hdesc, hash);
		if (err) {
			printk(KERN_ERR "[gosthash test] Test %d: Failed to "
			       "final gosthash. [ERR: %d]\n", i, err);
			goto out;
		}
		if (memcmp(ght->result, hash, GOST_HASH_DIGEST_SIZE)) {
			err = -EINVAL;
			printk(KERN_ERR "[gosthash test] Test %d: Failed!\n", i);
			print_hex_dump(KERN_ERR, "hash buffer: ", DUMP_PREFIX_OFFSET,
				       16, 1, hash, GOST_HASH_DIGEST_SIZE, 0);
			break;
		}

		memset(buf, 0, ght->tlen);
	}

out:
	if (tfm)
		crypto_free_hash(tfm);
	if (buf)
		kfree(buf);

	gosthash_paramset_id = def_type;
	return err;
}

static int __init gost_hash_mod_init(void)
{
	int ret;
	gost_subst_block_t *sb = gost_get_subst_block(GostHash_CustomBlock);

	BUG_ON(sb == NULL);
	memset(sb, 0, sizeof(*sb));
	ret = gost_select_subst_block(GOSTHASH_DEFAULT_SBT_ID,
				      GostHash_CustomBlock,
				      gosthash_custom_block,
				      &gosthash_paramset_id);
	if (ret)
		return ret;

	ret = crypto_register_shash(&gost_hash_le_alg);
	if (ret) {
		printk(KERN_ERR "GOST: Failed to register gosthash digest. "
		       "[ERR: %d]", ret);
		goto no_le_hash;
	}

	ret = crypto_register_shash(&gost_hash_st_alg);
	if (ret) {
		printk(KERN_ERR "GOST: Failed to register gosthash-st digest. "
		       "[ERR: %d]", ret);
		goto no_st_hash;
	}

	ret = do_gosthash_test();
	if (ret)
		goto err;

	ret = gost_debugfs_gosthash_init(gosthash_paramset_id);
	if (ret)
		goto err;

	return 0;
err:
	crypto_unregister_shash(&gost_hash_st_alg);
no_st_hash:
	crypto_unregister_shash(&gost_hash_le_alg);
no_le_hash:
	return ret;
}

static void __exit gost_hash_mod_fini(void)
{
	crypto_unregister_shash(&gost_hash_st_alg);
	crypto_unregister_shash(&gost_hash_le_alg);
	gost_debugfs_gosthash_fini();
}

module_init(gost_hash_mod_init);
module_exit(gost_hash_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GOST R 34.11-94 hash function");
