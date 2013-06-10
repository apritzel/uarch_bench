/*
 * Copyright 2011-2013 Andre Przywara <osp@andrep.de>
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

#if defined(__x86_64__)
#include "codegen_x86.h"
#include "ins_x86.h"
#else
#pragma GCC diagnostic error "-Wfatal-errors"
#error "architecture not supported"
#endif

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

/* if testing all opcodes, mark them as finished while we iterate the list */
#define PROCESSED  (1U << 31) 

#define ACTION_TEST 0
#define ACTION_DUMP 1
#define ACTION_LIST 2

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
	fprintf(outf, "\t-6     : generate code with 64-bit operands by default\n");
	fprintf(outf, "\t-n runs: repeat each run <runs> times and average\n");
	fprintf(outf, "\t-i iter: repeat the 8 instructions <iter> times in a\n");
	fprintf(outf, "\t         loop, default is 1 million\n");
	fprintf(outf, "\t-r loop: roll out the loops <loop> times, default: 8\n");
	fprintf(outf, "\t-c file: load binary code from file and execute that\n");
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
	int bits, bitness = DEFAULT_BITNESS;
	int all = 0;
	int verbose = 0;
	char *codefn = NULL;
	size_t mapsize = 4096;
	FILE *codefd = NULL;

	while ((opt = getopt(argc, argv, "h?d36r:n:i:c:lav")) != -1) {
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
		case '6':
			bitness = 64;
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
		case 'c':
			codefn = optarg;
			break;
		}
	}

	if (action == ACTION_LIST) {
		char strbuf[64];
		for (curtest = tests; curtest->name != NULL; curtest++) {
			fprintf(stdout, "%s\n", format_ins(curtest, strbuf, 64));
		}
		return 0;
	}

	if (codefn != NULL) {

		codefd = fopen(codefn, "rb");
		if (codefd == NULL) {
			perror("open");
			exit(2);
		}
		if (fseek(codefd, 0, SEEK_END) == 0) {
			mapsize = (ftell(codefd) + 4095) & ~4095UL;
			fseek(codefd, 0, SEEK_SET);
		}
	}

	ptr = mmap(NULL, mapsize, PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr == NULL) {
		perror("mapping executable memory");
		return 1;
	}
	if (codefn != NULL) {
		fread(ptr, 1, mapsize, codefd);
		fclose(codefd);
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
			if ((!all && codefn == NULL) &&
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

			if (codefn == NULL) {
				len = populate_code_page(ptr, curtest, rollout, bits == 64,
					iterations);
				if (action == ACTION_DUMP) {
					write(1, ptr, len);
					break;
				}
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

	munmap(ptr, mapsize);

	return 0;
}
