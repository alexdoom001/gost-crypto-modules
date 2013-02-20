obj-$(CONFIG_CRYPTO_GOST_CRYPT) += gostcrypt.o gost_debugfs.o
obj-$(CONFIG_CRYPTO_GOST_HASH94) += gosthash.o
obj-$(CONFIG_CRYPTO_GOST_HASH2012) += stribog.o

CFLAGS_stribog.o = $(call cc-option,-msse2,)
