/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LKMRKDET_ENTRY_DECODE_H
#define LKMRKDET_ENTRY_DECODE_H

/* Bounded entry-pattern recognition, NOT a general disassembler. */
#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 rk_u8;
typedef u32 rk_u32;
typedef u64 rk_u64;
typedef s64 rk_s64;
#else
#include <stdint.h>
#include <stddef.h>
typedef uint8_t rk_u8;
typedef uint32_t rk_u32;
typedef uint64_t rk_u64;
typedef int64_t rk_s64;
#endif

enum rk_arch { RK_X86_64, RK_ARM64 };
enum rk_pattern { RK_NONE, RK_BRANCH, RK_CALL, RK_BREAKPOINT, RK_INDIRECT };
struct rk_entry {
	enum rk_pattern kind;
	const char *name;
	rk_u64 target;
	rk_u64 literal;
	unsigned int offset;
};

static inline rk_u32 rk_le32(const rk_u8 *b)
{
	return (rk_u32)b[0] | (rk_u32)b[1] << 8 |
	       (rk_u32)b[2] << 16 | (rk_u32)b[3] << 24;
}

static inline rk_u64 rk_le64(const rk_u8 *b)
{
	return (rk_u64)rk_le32(b) | (rk_u64)rk_le32(b + 4) << 32;
}

static inline rk_s64 rk_sign_extend(rk_u64 value, unsigned int bits)
{
	rk_u64 sign = (rk_u64)1 << (bits - 1);
	return value & sign ? -(rk_s64)(((rk_u64)1 << bits) - value) : (rk_s64)value;
}

static inline struct rk_entry rk_decode_entry(enum rk_arch arch,
		const rk_u8 *b, size_t len, rk_u64 address)
{
	struct rk_entry e = { RK_NONE, "none", 0, 0, 0 };
	unsigned int off = 0;
	rk_s64 displacement;
	rk_u32 insn;

	if (arch == RK_X86_64) {
		/* Skip ENDBR64 only. Do not search arbitrary bytes for opcodes. */
		if (len >= 4 && b[0] == 0xf3 && b[1] == 0x0f &&
		    b[2] == 0x1e && b[3] == 0xfa)
			off = 4;
		e.offset = off;
		if (len <= off)
			return e;
		b += off;
		len -= off;
		address += off;
		if (len >= 12 && b[0] == 0x48 && b[1] == 0xb8 &&
		    b[10] == 0xff && b[11] == 0xe0) {
			e.kind = RK_BRANCH;
			e.name = "x86_movabs_jmp_rax";
			e.target = rk_le64(b + 2);
		} else if (len >= 5 && (b[0] == 0xe9 || b[0] == 0xe8)) {
			e.kind = b[0] == 0xe9 ? RK_BRANCH : RK_CALL;
			e.name = b[0] == 0xe9 ? "x86_jmp_rel32" : "x86_call_rel32";
			displacement = rk_sign_extend(rk_le32(b + 1), 32);
			e.target = address + 5 + displacement;
		} else if (len >= 2 && b[0] == 0xeb) {
			e.kind = RK_BRANCH;
			e.name = "x86_jmp_rel8";
			e.target = address + 2 + rk_sign_extend(b[1], 8);
		} else if (len >= 6 && b[0] == 0xff && b[1] == 0x25) {
			e.kind = RK_INDIRECT;
			e.name = "x86_jmp_rip_indirect";
			e.literal = address + 6 + rk_sign_extend(rk_le32(b + 2), 32);
		} else if (b[0] == 0xcc) {
			e.kind = RK_BREAKPOINT;
			e.name = "x86_int3";
		}
		return e;
	}

	if (len < 4)
		return e;
	insn = rk_le32(b);
	/* BTI, BTI c, BTI j and BTI jc landing pads. */
	if ((insn & 0xfffffc1fU) == 0xd503241fU) {
		off = 4;
		e.offset = off;
		if (len < 8)
			return e;
		insn = rk_le32(b + off);
		address += off;
	}
	if ((insn & 0x7c000000U) == 0x14000000U) {
		e.kind = insn & 0x80000000U ? RK_CALL : RK_BRANCH;
		e.name = e.kind == RK_CALL ? "arm64_bl_imm26" : "arm64_b_imm26";
		e.target = address + rk_sign_extend(insn & 0x03ffffffU, 26) * 4;
	} else if ((insn & 0xffe0001fU) == 0xd4200000U) {
		e.kind = RK_BREAKPOINT;
		e.name = "arm64_brk";
	} else if (len >= off + 8 && (insn & 0xff000000U) == 0x58000000U) {
		/* LDR Xt, literal; BR Xt. Read the literal separately, nofault. */
		rk_u32 branch = rk_le32(b + off + 4);
		if ((branch & 0xfffffc1fU) == 0xd61f0000U &&
		    ((branch >> 5) & 31) == (insn & 31)) {
			e.kind = RK_INDIRECT;
			e.name = "arm64_ldr_literal_br";
			e.literal = address + rk_sign_extend((insn >> 5) & 0x7ffff, 19) * 4;
		}
	}
	return e;
}
#endif
