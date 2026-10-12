/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "entry_decode.h"

int main(void)
{
	struct rk_entry e;
	rk_u8 backward[] = { 0xe9, 0xfb, 0xff, 0xff, 0xff };
	rk_u8 endbr[] = { 0xf3, 0x0f, 0x1e, 0xfa, 0xe9, 1, 0, 0, 0 };
	rk_u8 mov[] = { 0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xff, 0xe0 };
	rk_u8 indirect[] = { 0xff, 0x25, 0xfa, 0xff, 0xff, 0xff };
	rk_u8 normal[] = { 0x55, 0x48, 0x89, 0xe5, 0xe9, 0, 0, 0, 0 };
	rk_u8 arm_back[] = { 0xff, 0xff, 0xff, 0x17 };
	rk_u8 arm_bti[] = { 0x5f, 0x24, 0x03, 0xd5, 1, 0, 0, 0x14 };
	rk_u8 arm_literal[] = { 0x50, 0, 0, 0x58, 0, 2, 0x1f, 0xd6 };
	rk_u8 arm_brk[] = { 0, 0, 0x20, 0xd4 };
	size_t n;

	e = rk_decode_entry(RK_X86_64, backward, sizeof(backward), 0x1000);
	assert(e.kind == RK_BRANCH && e.target == 0x1000);
	e = rk_decode_entry(RK_X86_64, endbr, sizeof(endbr), 0x1000);
	assert(e.kind == RK_BRANCH && e.offset == 4 && e.target == 0x100a);
	e = rk_decode_entry(RK_X86_64, mov, sizeof(mov), 0);
	assert(e.kind == RK_BRANCH && e.target == 0x1122334455667788ULL);
	for (n = 0; n < sizeof(mov); n++)
		assert(rk_decode_entry(RK_X86_64, mov, n, 0).kind == RK_NONE);
	e = rk_decode_entry(RK_X86_64, indirect, sizeof(indirect), 0x1000);
	assert(e.kind == RK_INDIRECT && e.literal == 0x1000);
	assert(rk_decode_entry(RK_X86_64, normal, sizeof(normal), 0).kind == RK_NONE);
	e = rk_decode_entry(RK_ARM64, arm_back, sizeof(arm_back), 0x1000);
	assert(e.kind == RK_BRANCH && e.target == 0xffc);
	e = rk_decode_entry(RK_ARM64, arm_bti, sizeof(arm_bti), 0x1000);
	assert(e.kind == RK_BRANCH && e.offset == 4 && e.target == 0x1008);
	e = rk_decode_entry(RK_ARM64, arm_literal, sizeof(arm_literal), 0x1000);
	assert(e.kind == RK_INDIRECT && e.literal == 0x1008);
	arm_literal[4] = 0x20; /* Different source register must not match. */
	assert(rk_decode_entry(RK_ARM64, arm_literal, sizeof(arm_literal), 0).kind == RK_NONE);
	assert(rk_decode_entry(RK_ARM64, arm_brk, sizeof(arm_brk), 0).kind == RK_BREAKPOINT);
	for (n = 0; n < 4; n++)
		assert(rk_decode_entry(RK_ARM64, arm_back, n, 0).kind == RK_NONE);
	puts("Entry recognition: signed branches, bounds, landing pads, literal branches and non-entry bytes passed.");
	return 0;
}
