#ifndef __CODEGEN_X86_H__
#define __CODEGEN_X86_H__
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

#ifdef __x86_64__
#define DEFAULT_BITNESS 64
#else
#define DEFAULT_BITNESS 32
#endif

#define SINGLEOP   (1U <<  0)
#define IMM8       (1U <<  1)
#define IMM32      (1U <<  2)  
#define MEMOP      (1U <<  3)
#define HASSIB     (1U <<  4)
#define SAMEOP     (1U <<  5)
#define SCALE2     (1U <<  6)
#define SCALE4     (1U <<  7)
#define SCALE8     (1U <<  8)
#define REPPREF    (1U <<  9)
#define PERMREG    (1U << 10)

struct instest_x86 {
	const char *name;
	int inslen;
	unsigned char prefix;
	unsigned opcode;
	unsigned opcode_ext;
	unsigned flags;
	unsigned imm;
	struct instest_x86 *next;
};

#define instest instest_x86

int populate_code_page(unsigned char *ptr, struct instest_x86 *opcodelist,
	int unrolled, int sixtyfour, unsigned iterations);

char* format_ins(struct instest *ins, char *buffer, int buflen);

#endif
