#include <asm/i387.h>

#define load_xmm_macro(DST_XMM_0, DST_XMM_1, DST_XMM_2, DST_XMM_3) \
	asm ( \
	"movdqu %0, %%"#DST_XMM_0";" \
	"movdqu %1, %%"#DST_XMM_1";" \
	"movdqu %2, %%"#DST_XMM_2";" \
	"movdqu %3, %%"#DST_XMM_3";" \
	::"m"(data[0]), "m"(data[2]), "m"(data[4]), "m"(data[6]) \
	:"%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", "%xmm9", \
	"%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15");

#define xor_xmm_macro(SRC_XMM_0, SRC_XMM_1, SRC_XMM_2, SRC_XMM_3, DST_XMM_0, DST_XMM_1, DST_XMM_2, DST_XMM_3) \
	asm ( \
	"pxor %%"#SRC_XMM_0", %%"#DST_XMM_0";" \
	"pxor %%"#SRC_XMM_1", %%"#DST_XMM_1";" \
	"pxor %%"#SRC_XMM_2", %%"#DST_XMM_2";" \
	"pxor %%"#SRC_XMM_3", %%"#DST_XMM_3";" \
	:::"%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", "%xmm9", \
	"%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15");

#define LPS_xmm_macro(SRC_XMM_0, SRC_XMM_1, SRC_XMM_2, SRC_XMM_3, DST_XMM, IDX_0, IDX_1) \
	asm( \
	"pextrw $"#IDX_0", %%"#SRC_XMM_0", %%eax;" \
	"pextrw $"#IDX_0", %%"#SRC_XMM_1", %%ecx;" \
	"pextrw $"#IDX_1", %%"#SRC_XMM_0", %%ebx;" \
	"pextrw $"#IDX_1", %%"#SRC_XMM_1", %%edx;" \
	\
	"movzbl %%al, %%r8d;" \
	"movzbl %%bl, %%r9d;" \
	"movzbl %%cl, %%r10d;" \
	"movq (%[table], %%r8, 8), %%r12;" \
	"movzbl %%dl, %%r11d;" \
	"movzbl %%ah, %%eax;" \
	"xor 0x800(%[table], %%r9, 8), %%r12;" \
	"movzbl %%bh, %%ebx;" \
	"movq (%[table], %%rax, 8), %%r13;" \
	"movzbl %%ch, %%ecx;" \
	"movzbl %%dh, %%edx;" \
	\
	"xor 0x800(%[table], %%rbx, 8), %%r13;" \
	"xor 0x1000(%[table], %%r10, 8), %%r12;" \
	"pextrw $"#IDX_0", %%"#SRC_XMM_2", %%eax;" \
	"xor 0x1000(%[table], %%rcx, 8), %%r13;" \
	"xor 0x1800(%[table], %%r11, 8), %%r12;" \
	"pextrw $"#IDX_1", %%"#SRC_XMM_2", %%ebx;" \
	"xor 0x1800(%[table], %%rdx, 8), %%r13;" \
	\
	"pextrw $"#IDX_0", %%"#SRC_XMM_3", %%ecx;" \
	"pextrw $"#IDX_1", %%"#SRC_XMM_3", %%edx;" \
	\
	"movzbl %%al, %%r8d;" \
	"movzbl %%bl, %%r9d;" \
	"movzbl %%cl, %%r10d;" \
	"xor 0x2000(%[table], %%r8, 8), %%r12;" \
	"movzbl %%dl, %%r11d;" \
	"movzbl %%ah, %%eax;" \
	"xor 0x2800(%[table], %%r9, 8), %%r12;" \
	"movzbl %%bh, %%ebx;" \
	"xor 0x2000(%[table], %%rax, 8), %%r13;" \
	"movzbl %%ch, %%ecx;" \
	"movzbl %%dh, %%edx;" \
	\
	"xor 0x2800(%[table], %%rbx, 8), %%r13;" \
	"xor 0x3000(%[table], %%r10, 8), %%r12;" \
	"xor 0x3000(%[table], %%rcx, 8), %%r13;" \
	"xor 0x3800(%[table], %%r11, 8), %%r12;" \
	"xor 0x3800(%[table], %%rdx, 8), %%r13;" \
	\
	"movq %%r12, %%"#DST_XMM";" \
	"movq %%r13, %%xmm3;" \
	"movlhps %%xmm3, %%"#DST_XMM";" \
	::[table]"q"(table): \
	 "%rax","%rbx","%rcx","%rdx","%r8","%r9","%r10","%r11", "%r12","%r13", \
	 "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", "%xmm9", \
	 "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15");

static inline void load_xmm_4(uint64_t *data)
{
	load_xmm_macro(xmm4, xmm5, xmm6, xmm7);
}

static inline void load_xmm_8(uint64_t *data)
{
	load_xmm_macro(xmm8, xmm9, xmm10, xmm11);
}

static inline void load_xmm_12(uint64_t *data)
{
	load_xmm_macro(xmm12, xmm13, xmm14, xmm15);
}

static inline void xor_xmm_4_12(void)
{
	xor_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm12, xmm13, xmm14, xmm15);
}

static inline void xor_xmm_8_4(void)
{
	xor_xmm_macro(xmm8, xmm9, xmm10, xmm11, xmm4, xmm5, xmm6, xmm7);
}

static inline void xor_xmm_8_12(void)
{
	xor_xmm_macro(xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15);
}

static inline void xor_xmm_12_4(void)
{
	xor_xmm_macro(xmm12, xmm13, xmm14, xmm15, xmm4, xmm5, xmm6, xmm7);
}

static inline void LPS_xmm_4_8(void)
{
	uint64_t *table = (uint64_t*)lps_table;
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm8, 0, 4);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm9, 1, 5);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm10, 2, 6);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm11, 3, 7);
}

static inline void LPS_xmm_4_12(void)
{
	uint64_t *table = (uint64_t*)lps_table;
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm12, 0, 4);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm13, 1, 5);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm14, 2, 6);
	LPS_xmm_macro(xmm4, xmm5, xmm6, xmm7, xmm15, 3, 7);
}

static inline void LPS_xmm_12_4(void)
{
	uint64_t *table = (uint64_t*)lps_table;
	LPS_xmm_macro(xmm12, xmm13, xmm14, xmm15, xmm4, 0, 4);
	LPS_xmm_macro(xmm12, xmm13, xmm14, xmm15, xmm5, 1, 5);
	LPS_xmm_macro(xmm12, xmm13, xmm14, xmm15, xmm6, 2, 6);
	LPS_xmm_macro(xmm12, xmm13, xmm14, xmm15, xmm7, 3, 7);
}


/* hash is about 5% faster if g_N() is a noinline function */
static noinline void g_N(const void *N, const void *m, void *h)
{
	int i;

	kernel_fpu_begin();
	load_xmm_4((uint64_t*)N);
	load_xmm_8((uint64_t*)h);
	xor_xmm_8_4();

	LPS_xmm_4_12();
	load_xmm_4((uint64_t*)m);
	xor_xmm_12_4();
	load_xmm_8((uint64_t*)C[0]);
	xor_xmm_8_12();

	for(i = 0; i < 11; i++) {
		LPS_xmm_4_8();
		LPS_xmm_12_4();
		load_xmm_12((uint64_t*)(C[i+1]));
		xor_xmm_4_12();
		xor_xmm_8_4();
	}
	LPS_xmm_4_8();
	LPS_xmm_12_4();
	xor_xmm_4_12();
	xor_xmm_8_4();

	load_xmm_8((uint64_t*)h);
	xor_xmm_8_4();
	load_xmm_8((uint64_t*)m);
	xor_xmm_8_4();

	/* there are some optimization problems in gcc version 4.4.5 with
	   inline assembler placed in subroutine if g_N() is an inline function,
	   so it is necessary to place following code just here */
	asm (
	"movdqu %%xmm4, %0;"
	"movdqu %%xmm5, %1;"
	"movdqu %%xmm6, %2;"
	"movdqu %%xmm7, %3;"
	:"=m"(((u8 *)h)[0]), "=m"(((u8 *)h)[16]), "=m"(((u8 *)h)[32]), "=m"(((u8 *)h)[48])
	::"%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8", "%xmm9",
	  "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15");
	kernel_fpu_end();
}
