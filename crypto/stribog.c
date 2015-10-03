/*
 * GOST 34.11--2012 implementation
 *
 */

#include <crypto/internal/hash.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include "stribog.h"

/* A, sbox (pi prime) and C constants */
#include "stribog_const.c"

/*
 * LPS function table, precomputed at start from A, sbox and P transformation
 */
static uint64_t lps_table[8][256];

static void add512nums(const void *n1, const void *n2, void *res)
{
	const uint64_t *N1 = n1, *N2 = n2;
	uint64_t *R = res;
	uint64_t s, ai, bi;
	unsigned int i, carry = 0;

	for (i = 0; i < 8; i++) {
		ai = le64_to_cpu(N1[i]);
		bi = le64_to_cpu(N2[i]);
		s = ai + bi + carry;
		if (s < ai || s < bi)
			carry = 1;
		else
			carry = 0;
		R[i] = cpu_to_le64(s);
	}
}

static void add64to512num(uint64_t a, void *b)
{
	uint64_t s, bi;
	uint64_t *B = b;
	unsigned int i;

	for (i = 0; i < 8; i++) {
		bi = le64_to_cpu(B[i]);
		s = bi + a;
		B[i] = cpu_to_le64(s);
		if (s < bi)
			a = 1;
		else
			break;
	}
}

#if defined(__SSE__) && defined(__x86_64__)
#include "stribog_sse.c"
#else

static void xor512vecs(const void *v1, const void *v2, void *res)
{
	const uint64_t *V1 = v1, *V2 = v2;
	unsigned int i = 0;
	uint64_t *R = res;

	for (i = 0; i < 8; i++)
		R[i] = V1[i] ^ V2[i];
}

static void LPS(uint8_t *state)
{
	uint64_t return_state[8] = {};
	unsigned int i, j;

	for (i = 0; i < 8; i++)
		for (j = 0; j < 8; j++)
			return_state[i] ^= lps_table[j][state[i + j*8]];

	memcpy(state, return_state, 64);
}

static void E(const void *m, void *K, void *state)
{
	unsigned int i = 0;

	xor512vecs(m, K, state);

	for(i = 0; i < 12; i++) {
		LPS(state);

		xor512vecs(K, C[i], K);
		LPS(K); /* K(i+1) */

		xor512vecs(state, K, state);
	}
}

static void g_N(const void *N, const void *m, void *h)
{
	uint8_t K[64], t[64];

	xor512vecs(N, h, K); /* K0 */

	LPS(K);

	E(m, K, t);

	xor512vecs(t, h, t);
	xor512vecs(t, m, h);
}
#endif

static int hash2012_block(struct shash_desc *desc, const u8 *data, unsigned int len)
{
	stribog_ctx *c = shash_desc_ctx(desc);
	const u8 *remblock, *curblock = data;

	if (c->rem_len != 0) {
		uint8_t rembytes;

		if (c->rem_len >= 64)
			/* Wrong remainder length */
			return -EINVAL;

		rembytes = 64 - c->rem_len;
		if (rembytes > len)
			rembytes = len;

		memcpy(c->remainder + c->rem_len, data, rembytes);
		c->rem_len += rembytes;
		if (c->rem_len < 64)
			return 0;

		g_N(c->N, c->remainder, c->h);
		add64to512num(512, c->N);
		add512nums(c->sigma, c->remainder, c->sigma);
		c->rem_len = 0;
		curblock += rembytes;
	}

	for (remblock = (data + len) - 64; curblock <= remblock;
	     curblock += 64) {
		g_N(c->N, curblock, c->h);
		add64to512num(512, c->N);
		add512nums(c->sigma, curblock, c->sigma);
	}

	if (curblock != data + len) {
		c->rem_len = data + len - curblock;
		memcpy(c->remainder, curblock, c->rem_len);
	}
	return 0;
}

static int gost_3411_2012_final(stribog_ctx *c)
{
	if (c->rem_len >= 64)
		/* Wrong remainder length */
		return -EINVAL;

	c->remainder[c->rem_len] = 1;
	memset(&c->remainder[c->rem_len + 1], 0, sizeof(c->remainder) - c->rem_len - 1);

	g_N(c->N, c->remainder, c->h);
	add64to512num(c->rem_len * 8, c->N);
	add512nums(c->sigma, c->remainder, c->sigma);

	memset(c->remainder, 0, sizeof(c->remainder));
	g_N(c->remainder, c->N, c->h);
	g_N(c->remainder, c->sigma, c->h);

	return 0;
}

static void __init init_stribog_lps_table(void)
{
	static int table_inited = 0;
	int i, j, k;

	if (table_inited == 0) {
		for (i = 0; i < 8; i++)
			for (j = 0; j < 256; j++) {
				uint64_t t = 0;
				uint8_t p = sbox[j];

				for (k = 0; k < 8; k++)
					if (p & (1 << k))
						t ^= A[((7 - i) * 8) + 7 - k];

				lps_table[i][j] = cpu_to_le64(t);
			}
	}

	table_inited = 1;
}

static int init_stribog_ctx_512(struct shash_desc *desc)
{
	stribog_ctx *c = shash_desc_ctx(desc);

	memset(c, 0, sizeof(stribog_ctx));
	return 0;
}

static int init_stribog_ctx_256(struct shash_desc *desc)
{
	stribog_ctx *c = shash_desc_ctx(desc);

	memset(c, 0, sizeof(stribog_ctx));
	memset(c->h, 1, sizeof(c->h));
	return 0;
}

static int _gost_3411_2012_final_512(struct shash_desc *desc, u8 *md)
{
	stribog_ctx *c = shash_desc_ctx(desc);
	int ret;

	ret = gost_3411_2012_final(c);
	if (!ret)
		memcpy(md, c->h, 64);

	return ret;
}

static int _gost_3411_2012_final_256(struct shash_desc *desc, u8 *md)
{
	stribog_ctx *c = shash_desc_ctx(desc);
	int ret;

	ret = gost_3411_2012_final(c);
	if (!ret)
		memcpy(md, c->h + 32, 32);

	return ret;
}

static int stribog_import(struct shash_desc *desc, const void *in)
{
	stribog_ctx *c = shash_desc_ctx(desc);

	memcpy(c, in, sizeof(stribog_ctx));
	return 0;
}

static int stribog_export(struct shash_desc *desc, void *out)
{
	stribog_ctx *c = shash_desc_ctx(desc);

	memcpy(out, c, sizeof(stribog_ctx));
	return 0;
}

/*
 * Example 2 from standard's appendix A, phrase from The Tale of Igor's Campaign
 * cp1251 encoding, little endian byte order
 */
static const uint8_t __initdata selftest_data[] = {
	0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8,
	0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee,
	0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8,
	0x2c, 0x20, 0xe2, 0xe5, 0xfe, 0xf2, 0xfa, 0x20,
	0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1,
	0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20,
	0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
	0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb,
	0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb

};

static int __init gost_selftest_3411_2012_256(void)
{
	struct hash_desc hdesc;
	struct crypto_hash *tfm = NULL;
	struct scatterlist sg;
	u8 hash[32], *buf = NULL;
	int err = 0;

	static const uint8_t __initdata control_hash[] = {
		0x9d, 0xd2, 0xfe, 0x4e, 0x90, 0x40, 0x9e, 0x5d,
		0xa8, 0x7f, 0x53, 0x97, 0x6d, 0x74, 0x05, 0xb0,
		0xc0, 0xca, 0xc6, 0x28, 0xfc, 0x66, 0x9a, 0x74,
		0x1d, 0x50, 0x06, 0x3c, 0x55, 0x7e, 0x8f, 0x50
	};

	tfm = crypto_alloc_hash("gosthash12-256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		tfm = NULL;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to allocate "
		       "gosthash12-256 transform. [ERR: %d]\n", err);
		goto out;
	}

	hdesc.tfm = tfm;
	buf = kmalloc(sizeof(selftest_data), GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to allocate "
		       "%lu bytes for gosthash buffer!\n", sizeof(selftest_data));
		goto out;
	}
	memcpy(buf, selftest_data, sizeof(selftest_data));

	err = crypto_hash_init(&hdesc);
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to "
		       "init gosthash12-256 hash. [ERR: %d]\n", err);
		goto out;
	}
	sg_init_one(&sg, buf, sizeof(selftest_data));

	err = crypto_hash_update(&hdesc, &sg, sizeof(selftest_data));
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test ] Failed to "
		       "update gosthash12-256. [ERR: %d]\n", err);
		goto out;
	}

	err = crypto_hash_final(&hdesc, hash);
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to "
			       "finalize gosthash12-256. [ERR: %d]\n", err);
		goto out;
	}

	if (memcmp(control_hash, hash, 32)) {
		err = -EINVAL;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed gosthash12-256!\n");
		print_hex_dump(KERN_ERR, "hash buffer: ", DUMP_PREFIX_OFFSET,
			       16, 1, hash, 32, 0);
	}

out:
	if (tfm)
		crypto_free_hash(tfm);

	return err;
}

static int __init gost_selftest_3411_2012_512(void)
{
	struct hash_desc hdesc;
	struct crypto_hash *tfm = NULL;
	struct scatterlist sg;
	u8 hash[64], *buf = NULL;
	int err = 0;

	static const uint8_t __initdata control_hash[] = {
		0x1e, 0x88, 0xe6, 0x22, 0x26, 0xbf, 0xca, 0x6f,
		0x99, 0x94, 0xf1, 0xf2, 0xd5, 0x15, 0x69, 0xe0,
		0xda, 0xf8, 0x47, 0x5a, 0x3b, 0x0f, 0xe6, 0x1a,
		0x53, 0x00, 0xee, 0xe4, 0x6d, 0x96, 0x13, 0x76,
		0x03, 0x5f, 0xe8, 0x35, 0x49, 0xad, 0xa2, 0xb8,
		0x62, 0x0f, 0xcd, 0x7c, 0x49, 0x6c, 0xe5, 0xb3,
		0x3f, 0x0c, 0xb9, 0xdd, 0xdc, 0x2b, 0x64, 0x60,
		0x14, 0x3b, 0x03, 0xda, 0xba, 0xc9, 0xfb, 0x28
	};

	tfm = crypto_alloc_hash("gosthash12-512", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		tfm = NULL;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to allocate "
		       "gosthash12-512 transform. [ERR: %d]\n", err);
		goto out;
	}

	hdesc.tfm = tfm;
	buf = kmalloc(sizeof(selftest_data), GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to allocate "
		       "%lu bytes for gosthash buffer!\n", sizeof(selftest_data));
		goto out;
	}
	memcpy(buf, selftest_data, sizeof(selftest_data));

	err = crypto_hash_init(&hdesc);
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to "
		       "init gosthash12-512 hash. [ERR: %d]\n", err);
		goto out;
	}
	sg_init_one(&sg, buf, sizeof(selftest_data));

	err = crypto_hash_update(&hdesc, &sg, sizeof(selftest_data));
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test ] Failed to "
		       "update gosthash12-512. [ERR: %d]\n", err);
		goto out;
	}

	err = crypto_hash_final(&hdesc, hash);
	if (err) {
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed to "
			       "finalize gosthash12-512. [ERR: %d]\n", err);
		goto out;
	}

	if (memcmp(control_hash, hash, 64)) {
		err = -EINVAL;
		printk(KERN_ERR "[GOST 34.11-2012 test] Failed gosthash12-512!\n");
		print_hex_dump(KERN_ERR, "hash buffer: ", DUMP_PREFIX_OFFSET,
			       16, 1, hash, 64, 0);
	}

out:
	if (tfm)
		crypto_free_hash(tfm);

	return err;
}

static struct shash_alg stribog256_alg = {
	.digestsize	=	32,
	.init		=	init_stribog_ctx_256,
	.update		=	hash2012_block,
	.final		=	_gost_3411_2012_final_256,
	.export		=	stribog_export,
	.import		=	stribog_import,

	.descsize	=	sizeof(stribog_ctx),
	.statesize	=	sizeof(stribog_ctx),
	.base		=	{
		.cra_name	=	"gosthash12-256",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	64,
		.cra_module	=	THIS_MODULE,
	}
};

static struct shash_alg stribog512_alg = {
	.digestsize	=	64,
	.init		=	init_stribog_ctx_512,
	.update		=	hash2012_block,
	.final		=	_gost_3411_2012_final_512,
	.export		=	stribog_export,
	.import		=	stribog_import,

	.descsize	=	sizeof(stribog_ctx),
	.statesize	=	sizeof(stribog_ctx),
	.base		=	{
		.cra_name	=	"gosthash12-512",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	64,
		.cra_module	=	THIS_MODULE,
	}
};

static int __init stribog_mod_init(void)
{
	int ret = 0;

	init_stribog_lps_table();
	ret = crypto_register_shash(&stribog256_alg);
	if (ret) {
		printk(KERN_ERR "Failed to register GOST 34.11-2012-256 digest. "
		       "[ERR: %d]", ret);
		goto no_256_hash;
	}

	ret = crypto_register_shash(&stribog512_alg);
	if (ret) {
		printk(KERN_ERR "Failed to register GOST 34.11-2012-512 digest. "
		       "[ERR: %d]", ret);
		goto no_512_hash;
	}

	ret = gost_selftest_3411_2012_256();
	if (ret) {
		printk(KERN_ERR "GOST 34.11-2012-256 digest selftest failed. "
		       "[ERR: %d]", ret);
		goto err;
	}
	ret = gost_selftest_3411_2012_512();
	if (ret) {
		printk(KERN_ERR "GOST 34.11-2012-512 digest selftest failed. "
		       "[ERR: %d]", ret);
		goto err;
	}

	return 0;
err:
	crypto_unregister_shash(&stribog512_alg);
no_512_hash:
	crypto_unregister_shash(&stribog256_alg);
no_256_hash:
	return ret;
}

static void __exit stribog_mod_fini(void)
{
	crypto_unregister_shash(&stribog256_alg);
	crypto_unregister_shash(&stribog512_alg);
}

module_init(stribog_mod_init);
module_exit(stribog_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GOST R 34.11-2012 hash function");
