/*
 * Copyright 2011 Andre Przywara <osp@andrep.de>
 *
 * This file is part of uarch_bench (measuring instruction throughput)
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
 *
 * uarch_bench does:
 * - populate a page with assembly instructions in a loop
 * - jump to this code, with PMCs armed
 * - stop counting on return
 * - calculating IPC for that instruction
 *
 * For a quick start: $ ./insthru -a
 * $ ./insthru -h gives more options
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <linux/perf_event.h>

#ifndef HAVE_PERF_EVENT_OPEN_PROTO

#include <asm/unistd.h>

static inline int
sys_perf_event_open(struct perf_event_attr *attr,
	pid_t pid, int cpu, int group_fd,
	unsigned long flags)
{
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu,
		group_fd, flags);
}
#endif /* HAVE_PERF_EVENT_OPEN_PROTO */

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
/* if testing all opcodes, mark them as finished while we iterate the list */
#define PROCESSED  (1U << 31) 

struct instest {
	const char *name;
	int inslen;
	unsigned char prefix;
	unsigned opcode;
	unsigned opcode_ext;
	unsigned flags;
	unsigned imm;
	struct instest *next;
};

static unsigned char gen_modrm(struct instest *opcode, int reg)
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
		/* use DX as second source operand for dual op instructions */
		ret |= ((opcode->flags & SAMEOP) ? (reg & 0x07) : 2) << 3;
	}

	if (opcode->flags & MEMOP && !(opcode->flags & HASSIB)) {
		/* use DX as base register (in r/m) if needed */
		ret |= ((opcode->flags & SAMEOP) ? (reg & 0x07) : 2) << 0;
	}

	/* target register is in reg or r/m */
	ret |= (reg & 0x07) << ((opcode->flags & MEMOP) ? 3 : 0);

	if (opcode->flags & PERMREG)
		ret = (ret & 0xC0) | ((ret & 0x38) >> 3) | ((ret & 0x07) << 3);

	return ret;
}

static int gen_ins(struct instest *opcode, unsigned char *ptr, int sixtyfour,
	int src, int index, int tgt)
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

	*cur++ = gen_modrm(opcode, tgt);

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

int populate_code_page(unsigned char *ptr, struct instest *opcodelist,
	int unrolled, int sixtyfour, unsigned iterations)
{
	int i;
	int loop;
	uint32_t reg;
	unsigned char *cur;
	int jmpdist;
	struct instest *opcode = opcodelist;

    /* we use RAX, RBX, RSI, RDI, R8 .. R11 */
    /* ECX is used for the counter, EDX holds a value as a source operand */
	unsigned regs[8] = { 0, 3, 6, 7, 8, 9, 10, 11};

	unsigned char setup[32] = {
		0x50, 0x51, 0x52, 0x53, /* push rax, rcx, rdx, rbx */
		0x56, 0x57, 0x41, 0x50, 0x41, 0x51, /* push rsi, rdi, r8, r9 */
		0x41, 0x52, 0x41, 0x53, /* push r10, r11 */
		0xB9, 0x00, 0x00, 0x00, 0x00, /* mov $imm, %ecx (patched later) */
		0xBA, 0x00, 0x00, 0x00, 0x00, /* mov $imm, %edx (patched later) */
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
				opcode->flags & SAMEOP ? regs[i] : 2,
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

#define ACTION_TEST 0
#define ACTION_DUMP 1
#define ACTION_LIST 2

struct instest tests[] = {
/*   name, length, pref,   opcode,ext,     flags    , mod_rm, imm */
	{"or",      1, 0x00,   0x09,  0,                0, 0}, /* or  src,tgt */
	{"and",     1, 0x00,   0x21,  0,                0, 0}, /* and src,tgt */
	{"xor",     1, 0x00,   0x31,  0,                0, 0}, /* xor src,tgt */
	{"add",     1, 0x00,   0x01,  0,                0, 0}, /* add src,tgt */
	{"addi",    1, 0x00,   0x83,  0, SINGLEOP | IMM8, 1}, /* add $1, tgt */
	{"addi2",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 2}, /* add $2, tgt */
	{"addi4",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 4}, /* add $4, tgt */
	{"addi8",   1, 0x00,   0x83,  0, SINGLEOP | IMM8, 8}, /* add $8, tgt */
	{"adc",     1, 0x00,   0x11,  0,                0, 0}, /* adc src,tgt */
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
	{"mul",     1, 0x00,   0xF7,  4,        SINGLEOP, 0}, /* mul src */
	{"popcnt",  2, 0xF3, 0x0FB8,  0,          REPPREF, 0}, /* popcnt src, tgt */
	{"lzcnt",   2, 0xF3, 0x0FBD,  0,          REPPREF, 0}, /* lzcnt src, tgt */

	{NULL, 0}
};

static void usage(FILE *outf, const char *progname)
{
	fprintf(outf,
		"usage: %s [-h|-?] [-v] [-l] [-d] [-3] [-n nrruns] [-i iterations]\n",
		progname);
	fprintf(outf, "                     [-r rollout] [-a] test [test...]\n");
	fprintf(outf, "\n\t-h|-?  : this help\n");
	fprintf(outf, "\t-v     : verbose, display actual PMC counter values\n");
	fprintf(outf, "\t-l     : list all defined tests\n");
	fprintf(outf, "\t-d     : dump generated code to stdout\n");
	fprintf(outf, "\t-3     : generate code with 32-bit operands by default\n");
	fprintf(outf, "\t-n runs: repeat each run <runs> times and average\n");
	fprintf(outf, "\t-i iter: repeat the 8 instructions <iter> times in a\n");
	fprintf(outf, "\t         loop, default is 1 million\n");
	fprintf(outf, "\t-r loop: roll out the loops <loop> times, default: 8\n");
	fprintf(outf, "\t-a     : run all defined tests in a row\n");
	fprintf(outf, "\ttest   : test name, can be followed by .32 or .64 to\n");
	fprintf(outf, "\t         explicitly specify the operand bitness\n");
	fprintf(outf, "\t         use -l to get list of defined tests\n");
	return;
}


int main(int argc, char** argv)
{
	unsigned char *ptr;
	int perffd[2] = {0};
	struct perf_event_attr perfattr;
	void (*benchfunc)(void);
	uint64_t cnt, sum[2] = {0}, min[2] = {UINT64_MAX, UINT64_MAX}, max[2] = {0};
	int i;
	struct instest *curtest;
	int len;

	int opt;
	int action = ACTION_TEST;
	int nrruns = 20;
	int iterations = 1000000;
	int rollout = 8;
	int bitness = 64, bits;
	int all = 0;
	int verbose = 0;

	while ((opt = getopt(argc, argv, "h?d3r:n:i:lav")) != -1) {
		switch(opt) {
		case '?': case 'h':
			usage(stdout, argv[0]);
			return 0;
		case 'd':
			action = ACTION_DUMP;
			break;
		case 'l':
			action = ACTION_LIST;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'a':
			all = 1;
			break;
		case '3':
			bitness = 32;
			break;
		case 'n':
			nrruns = atoi(optarg);
			break;
		case 'i':
			iterations = atoi(optarg);
			break;
		case 'r':
			rollout = atoi(optarg);
			break;
		}
	}

	if (action == ACTION_LIST) {
		for (curtest = tests; curtest->name != NULL; curtest++) {
			fprintf(stdout, "%s (", curtest->name);
			if (curtest->inslen > 1)
				fprintf(stdout, "0x%02x ", curtest->opcode >> 8);
			fprintf(stdout, "0x%02x)\n", curtest->opcode & 0xFF);
		}
		return 0;
	}

	ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr == NULL) {
		perror("mapping executable memory");
		return 1;
	}
	benchfunc = (void*)ptr;

	if (action != ACTION_DUMP) {
		memset(&perfattr, 0, sizeof(perfattr));
		perfattr.type = PERF_TYPE_HARDWARE;
		perfattr.size = sizeof(perfattr);
		perfattr.config = PERF_COUNT_HW_CPU_CYCLES;
		perfattr.disabled = 1;
		perfattr.pinned = 1;
		perfattr.exclude_kernel = 1;
		perfattr.exclude_idle = 1;

		perffd[0] = sys_perf_event_open(&perfattr, 0, -1, -1, 0);
		if (perffd[0] < 0) {
			perror("sys_perf_event_open");
			return 3;
		}

		perfattr.config = PERF_COUNT_HW_INSTRUCTIONS;
		perffd[1] = sys_perf_event_open(&perfattr, 0, -1, -1 /*perffd[0]*/, 0);
		if (perffd[1] < 0) {
			perror("sys_perf_event_open");
			return 3;
		}
	}

	for (; optind < argc || all; optind += 1 - all) {
		for (curtest = tests; curtest->name != NULL; curtest++) {
			if (!all &&
				strncmp(curtest->name, argv[optind], strlen(curtest->name)))
				continue;
			if (all && (curtest->flags & PROCESSED))
				continue;
			curtest->flags |= PROCESSED;
			bits = bitness;
			if (!all) {
				switch(argv[optind][strlen(curtest->name)]) {
				case 0: break;
				case '.':
					bits = atoi(argv[optind] + strlen(curtest->name) + 1);
					break;
				default:
					continue;
				}
			}

			len = populate_code_page(ptr, curtest, rollout, bits == 64,
				iterations);
			if (action == ACTION_DUMP) {
				write(1, ptr, len);
				break;
			}
			sum[0] = 0; sum[1] = 0;
			min[0] = UINT64_MAX; min[1] = UINT64_MAX;
			max[0] = 0; max[1] = 0;
			for (i = 0; i < nrruns; i++) {
				ioctl(perffd[0], PERF_EVENT_IOC_RESET);
				ioctl(perffd[1], PERF_EVENT_IOC_RESET);

				ioctl(perffd[0], PERF_EVENT_IOC_ENABLE);
				ioctl(perffd[1], PERF_EVENT_IOC_ENABLE);
				benchfunc();
				ioctl(perffd[1], PERF_EVENT_IOC_DISABLE);
				ioctl(perffd[0], PERF_EVENT_IOC_DISABLE);

				read(perffd[0], &cnt, sizeof(cnt));
				sum[0] += cnt;
				if (cnt < min[0])
					min[0] = cnt;
				if (cnt > max[0])
					max[0] = cnt;

				read(perffd[1], &cnt, sizeof(cnt));
				sum[1] += cnt;
				if (cnt < min[1])
					min[1] = cnt;
				if (cnt > max[1])
					max[1] = cnt;
			}
			fprintf(stdout, "%8s.%d, %d runs%s", curtest->name, bits, nrruns,
				verbose ? ":\n" : ",");
			if (verbose) {
				fprintf(stdout,
					"  cycles       : %10"PRIu64" (min: %"PRIu64
					", max: %"PRIu64")\n",
					sum[0] / nrruns, min[0], max[0]);
				fprintf(stdout,
					"  instructions : %10"PRIu64" (min: %"PRIu64
					", max: %"PRIu64")\n",
					sum[1] / nrruns, min[1], max[1]);
			}
			fprintf(stdout,
				"  IPC: %.2f, cycles per iteration: %5.2f\n",
				sum[1] * 1.0 / sum[0], (double)sum[0] / (iterations * nrruns));
			break;
		}
		if (curtest->name == NULL) {
			if (all)
				break;
			fprintf(stderr, "test: %s is not defined, skipping.\n",
				argv[optind]);
		}
	}

	if (action != ACTION_DUMP) {
		close(perffd[1]);
		close(perffd[0]);
	}

	munmap(ptr, 4096);

	return 0;
}
