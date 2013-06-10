/*
 * Copyright 2011-2013 Andre Przywara <osp@andrep.de>
 *
 * This file is part of uarch_bench.
 *
 * uarch_bench is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * uarch_bench is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with uarch_bench.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "codegen_x86.h"

static unsigned char gen_modrm(struct instest_x86 *opcode, int src, int tgt)
{
	unsigned char ret;

	ret = 0;

	if (opcode->flags & SINGLEOP)
		ret |= opcode->opcode_ext << 3;

	if (opcode->flags & HASSIB)
		ret |= 4 << 0;

	if (opcode->flags & MEMOP) {
		/* addressing mode without immediate is 0x00 */
		/* addressing mode with base register + 8-bit immediate  */
		if (opcode->flags & IMM8)
			ret |= 0x40;
		/* addressing mode with base register + 32-bit immediate  */
		if (opcode->flags & IMM32)
			ret |= 0x80;
	} else {
		/* register/register version */
		ret |= 0xC0;
	}

	if (!(opcode->flags & MEMOP) && !(opcode->flags & SINGLEOP)) {
		/* use second source operand for dual op instructions */
		ret |= (((opcode->flags & SAMEOP) ? tgt : src) & 0x07) << 3;
	}

	if (opcode->flags & MEMOP && !(opcode->flags & HASSIB)) {
		/* use base register (in r/m) if needed */
		ret |= (((opcode->flags & SAMEOP) ? tgt : src) & 0x07) << 0;
	}

	/* target register is in reg or r/m */
	ret |= (tgt & 0x07) << ((opcode->flags & MEMOP) ? 3 : 0);

	if (opcode->flags & PERMREG) {
		if (opcode->flags & SINGLEOP)
			ret = (ret & 0xF8) | (src & 0x07);
		else
			ret = (ret & 0xC0) | ((ret & 0x38) >> 3) | ((ret & 0x07) << 3);
	}

	return ret;
}

static int gen_ins(struct instest_x86 *opcode, unsigned char *ptr,
	int sixtyfour, int src, int index, int tgt)
{
	unsigned char *cur = ptr;

	if (opcode->flags & REPPREF)
		*cur++ = opcode->prefix;

	/* do we need a REX prefix? */
	if (sixtyfour || tgt >= 8 || src >=8 || index >= 8) {
		*cur = 0x40;

		/* override default operand size to 64 bit */
		if (sixtyfour)
			*cur |= 0x48;

		/* set fourth register bit for either target or source */
		if (tgt >= 8)
			*cur |= (opcode->flags & (PERMREG | MEMOP)) ? 0x04 : 0x01;
		if (src >= 8)
			*cur |= (opcode->flags & (PERMREG | MEMOP)) ? 0x01 : 0x04;
		cur++;
	}

	if (opcode->inslen >= 4)
		*cur++ = (opcode->opcode >> 24) & 0xFF;

	if (opcode->inslen >= 3)
		*cur++ = (opcode->opcode >> 16) & 0xFF;

	if (opcode->inslen >= 2)
		*cur++ = (opcode->opcode >> 8) & 0xFF;

	*cur++ = opcode->opcode & 0xFF;

	*cur++ = gen_modrm(opcode, src, tgt);

	if (opcode->flags & HASSIB) {
		/* scale = 0 */
		*cur = 0 << 6;
		/* index = rCX or reg */
		*cur |= (index & 0x07) << 3;
		/* base = rDX or reg */
		*cur |= (src & 0x07) << 0;
		if (opcode->flags & SCALE2)
			*cur |= 1 << 6;
		if (opcode->flags & SCALE4)
			*cur |= 2 << 6;
		if (opcode->flags & SCALE8)
			*cur |= 3 << 6;
		cur++;
	}

	if (opcode->flags & IMM8)
		*cur++ = opcode->imm;

	if (opcode->flags & IMM32) {
		memcpy(cur, &opcode->imm, 4);
		cur += 4;
	}

	return cur - ptr;
}

int populate_code_page(unsigned char *ptr, struct instest_x86 *opcodelist,
	int unrolled, int sixtyfour, unsigned iterations)
{
	int i;
	int loop;
	uint32_t reg;
	unsigned char *cur;
	int jmpdist;
	struct instest_x86 *opcode = opcodelist;

    /* we use RAX, RBX, RSI, RDI, R8 .. R11 */
    /* ECX is used for the counter, EDX holds a value as a source operand */
	unsigned regs[8] = { 0, 3, 6, 7, 8, 9, 10, 11};

	unsigned char setup[32] = {
		0x50, 0x51, 0x52, 0x53, /* push rax, rcx, rdx, rbx */
		0x56, 0x57, 0x41, 0x50, 0x41, 0x51, /* push rsi, rdi, r8, r9 */
		0x41, 0x52, 0x41, 0x53, /* push r10, r11 */
		0xB9, 0x00, 0x00, 0x00, 0x00, /* mov $imm, %ecx (patched later) */
		0xBB, 0x00, 0x00, 0x00, 0x00, /* mov $imm, %ebx (patched later) */
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 /* NOP */
	};
	unsigned char leave[] = {
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, /*pop r10, r11, r9, r8*/
		0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, /* pop rbx, rdx, rcx, rax */
		0xC3 /* ret */};

	memcpy(ptr, setup, 32);

	/* fixup actual content of loop counter and the data value */
	reg = iterations;
	memcpy(ptr + 15, &reg, 4);
	reg = 0x39512804;
	memcpy(ptr + 20, &reg, 4);

	cur = ptr + 32;
	for (loop = 0; loop < unrolled; loop++) {
		for (i = 0; i < 8; i++) {
			cur += gen_ins(opcode, cur, sixtyfour,
				opcode->flags & SAMEOP ? regs[i] : 3,
				opcode->flags & SAMEOP ? regs[i] : 1,
				regs[i]);
			if (opcode->next != NULL)
				opcode = opcode->next;
		}
	}

	*cur++ = 0xFF;
	*cur++ = 0xC9;		/* dec %ecx */
	jmpdist = (ptr + 32 - cur - 2);
	if (jmpdist < -128) {
		jmpdist -= 4;
		*cur++ = 0x0f;
		*cur++ = 0x85;
		memcpy(cur, &jmpdist, 4);
		cur += 4;
	} else {
		*cur++ = 0x75;		/* jne ... */
		*cur++ = (char)jmpdist;
	}

	memcpy(cur, leave, sizeof(leave));
	cur++;

	return (cur - ptr) + sizeof(leave);
}

char* format_ins(struct instest *ins, char *buffer, int buflen)
{
	int written;

	written = snprintf(buffer, buflen, "%s (", ins->name);
	if (ins->inslen > 1)
		written += snprintf(buffer + written, buflen - written, "0x%02x ",
			ins->opcode >> 8);
	written += snprintf(buffer + written, buflen - written, "%02x)",
		ins->opcode & 0xFF);
	return buffer;
}
