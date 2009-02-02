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

/* Cipher context includes key and preprocessed substitution block */
typedef struct {
	u32 k[8];
	/* Constant s-boxes */
	u32 k87[256],k65[256],k43[256],k21[256];
} gost_ctx_t;

void gost_subst_block_init(gost_ctx_t *c);
void gost_enc_with_key(gost_ctx_t *c, u8 *key, u8 *inblock, u8 *outblock);

#endif /* _GOST_H_ */
