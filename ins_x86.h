#ifndef __INS_X86_H__
#define __INS_X86_H__
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

#include "codegen_x86.h"

struct instest_x86 tests[] = {
/*   name, length, pref, opcode,ext,     flags       , imm */
	{"or",      1, 0x00,   0x09,  0,                0, 0}, /* or  src,tgt */
	{"and",     1, 0x00,   0x21,  0,                0, 0}, /* and src,tgt */
	{"xor",     1, 0x00,   0x31,  0,                0, 0}, /* xor src,tgt */
	{"add",     1, 0x00,   0x01,  0,                0, 0}, /* add src,tgt */
	{"addi",    1, 0x00,   0x83,  0, SINGLEOP | IMM8, 1}, /* add $1, tgt */
	{"addi2",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 2}, /* add $2, tgt */
	{"addi4",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 4}, /* add $4, tgt */
	{"addi8",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 8}, /* add $8, tgt */
	{"adc",     1, 0x00,   0x11,  0,                0, 0}, /* adc src,tgt */
	{"xadd",    2, 0x00, 0x0FC1,  0,                0, 0}, /* xadd src,tgt */
	{"xchg",    1, 0x00,   0x87,  0,                0, 0}, /* xchg src,tgt */
	{"sub",     1, 0x00,   0x29,  0,                0, 0}, /* sub src,tgt */
	{"sbb",     1, 0x00,   0x1B,  0,                0, 0}, /* sbb src,tgt */
	{"inc",     1, 0x00,   0xFF,  0,        SINGLEOP, 0}, /* inc tgt */
	{"dec",     1, 0x00,   0xFF,  1,        SINGLEOP, 0}, /* dec tgt */
	{"mov",     1, 0x00,   0x89,  0,                0, 0}, /* mov src,tgt */
	{"neg",     1, 0x00,   0xF7,  3,        SINGLEOP, 0}, /* neg tgt */
	{"not",     1, 0x00,   0xF7,  2,        SINGLEOP, 0}, /* not tgt */
	{"shl",     1, 0x00,   0xD1,  4,        SINGLEOP, 0}, /* shl tgt */
	{"shl3",    1, 0x00,   0xC1,  4, SINGLEOP | IMM8, 3}, /* shl $3,tgt */
	{"leam",    1, 0x00,   0x8D,  0,            MEMOP, 0}, /* lea (src),tgt */
	{"leai",    1, 0x00,   0x8D,  0,MEMOP | IMM8 | SAMEOP, 1}, /* lea $1(tgt),tgt */
	{"leas",    1, 0x00,   0x8D,  0,MEMOP | HASSIB | SCALE2 | SAMEOP, 0}, /* lea (,tgt,1) */
	{"leaai",   1, 0x00,   0x8D,  0,     MEMOP | IMM8, 4}, /* lea $4(src),tgt */
	{"leaa3",   1, 0x00,   0x8D,  0,   MEMOP | HASSIB, 0}, /* lea (src, src2),tgt */
	{"leaa4",   1, 0x00,   0x8D,  0,MEMOP | HASSIB | IMM8, 4}, /* lea $4(src, src2), tgt */
	{"leacplx", 1, 0x00,   0x8D,  0,MEMOP | HASSIB | IMM8 | SCALE4, 16}, /* lea $16(src,src2,4),tgt */
	{"imul",    2, 0x00, 0x0FAF,  0,          PERMREG, 0}, /* imul src, tgt */
	{"mul",     1, 0x00,   0xF7,  4,         SINGLEOP, 0}, /* mul src */
	{"popcnt",  2, 0xF3, 0x0FB8,  0,          REPPREF, 0}, /* popcnt src, tgt */
	{"lzcnt",   2, 0xF3, 0x0FBD,  0,          REPPREF, 0}, /* lzcnt src, tgt */
	{"div",     1, 0x00,   0xF7,  6,SINGLEOP | PERMREG,  0}, /* div tgt */
#if 0
	{"idiv",    1, 0x00,   0xF7,  7,         SINGLEOP, 0}, /* idiv src */
#endif

	{NULL, 0}
/*   name, length, pref, opcode,ext,     flags       , imm */
};

#endif
