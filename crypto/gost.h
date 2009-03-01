#ifndef _GOST_H_
#define _GOST_H_

/* Internal representation of GOST substitution blocks */
typedef struct {
	u8 k8[16];
	u8 k7[16];
	u8 k6[16];
	u8 k5[16];
	u8 k4[16];
	u8 k3[16];
	u8 k2[16];
	u8 k1[16];
} gost_subst_block_t;

#define GOST_SUBST_BLOCK_SIZE 128

/* Packed representation of GOST S-Boxes */
typedef struct {
	u32 k87[256], k65[256], k43[256], k21[256];
} gost_sbox_t;

/* Cipher context includes key and preprocessed substitution block */
typedef struct {
	u32 k[8];
	gost_sbox_t *sbox;
} gost_ctx_t;

typedef struct {
	unsigned long long len;
	gost_ctx_t cipher_ctx;
	int left;
	u8 H[32];
	u8 S[32];
	u8 remainder[32];
	int format;
} gost_hash_ctx_t;

#define GOSTHASH_LE  0
#define GOSTHASH_BE  1

/* Gost substitutoin block types */
enum gost_subst_block_type {
	GostR3411_94_TestParamSet = 0,
	GostR3411_94_CryptoProParamSet,
	Gost28147_TestParamSet,
	Gost28147_CryptoProParamSetA,
	Gost28147_CryptoProParamSetB,
	Gost28147_CryptoProParamSetC,
	Gost28147_CryptoProParamSetD,
	GostCrypt_CustomBlock,
	GostHash_CustomBlock,
};

#define GOST_SBT_NUMBLOCKS	9
#define GOST_SBT_FIRST		GostR3411_94_TestParamSet
#define GOST_SBT_LAST_USR	Gost28147_CryptoProParamSetD
#define GOST_SBT_LAST           GostHash_CustomBlock

#define GOST_HASH_DIGEST_SIZE		32
#define GOST_HASH_HMAC_BLOCK_SIZE	32


#define GOSTCRYPT_DEFAULT_SBT_ID Gost28147_CryptoProParamSetA
#define GOSTHASH_DEFAULT_SBT_ID  GostR3411_94_CryptoProParamSet

void gost_subst_block_init(gost_ctx_t *c, enum gost_subst_block_type btype);
void gost_enc_with_key(gost_ctx_t *c, u8 *key, u8 *inblock, u8 *outblock);
gost_subst_block_t *gost_get_subst_block(enum gost_subst_block_type type);
gost_sbox_t *gost_get_sbox(enum gost_subst_block_type type);
int gost_select_subst_block(enum gost_subst_block_type default_type,
			    enum gost_subst_block_type custom_type,
			    const char *subst_block,
			    int *out_type);
int gost_setup_custom_block_cmdline(const char *prefix,
				    const char *str, char *out_str);

int gost_debugfs_init(void);
void gost_debugfs_fini(void);
int gost_debugfs_gosthash_init(int subst_id);
void gost_debugfs_gosthash_fini(void);
int gost_debugfs_gostcrypt_init(int subst_id);
void gost_debugfs_gostcrypt_fini(void);

#endif /* _GOST_H_ */
