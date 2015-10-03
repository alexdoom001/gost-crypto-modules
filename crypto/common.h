/*
 * Linux kernel Cryptographic API.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H  1

/* Linux >= 3.18 uses this macro to name autoloaded modules */
#ifndef MODULE_ALIAS_CRYPTO
#define MODULE_ALIAS_CRYPTO(name)	MODULE_ALIAS(name)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
#include <linux/crypto.h>
#else
#include <crypto/skcipher.h>

#define crypto_ablkcipher			crypto_skcipher
#define crypto_alloc_ablkcipher			crypto_alloc_skcipher
#define crypto_free_ablkcipher			crypto_free_skcipher
#define crypto_ablkcipher_setkey		crypto_skcipher_setkey
#define crypto_ablkcipher_clear_flags		crypto_skcipher_clear_flags
#define crypto_ablkcipher_encrypt		crypto_skcipher_encrypt
#define crypto_ablkcipher_decrypt		crypto_skcipher_decrypt

#define ablkcipher_request			skcipher_request
#define ablkcipher_request_alloc		skcipher_request_alloc
#define ablkcipher_request_free			skcipher_request_free
#define ablkcipher_request_set_callback		skcipher_request_set_callback
#define ablkcipher_request_set_crypt		skcipher_request_set_crypt
#endif

#endif  /* CRYPTO_COMMON_H */
