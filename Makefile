SH=/bin/sh
CC=gcc
CFLAGS=-Wall -O
LDFLAGS=

ARCH=$(shell uname -m)
ifeq ($(ARCH),x86_64)
CODEGEN=codegen_x86.o
all: insthru
else ifeq ($(ARCH),i686)
CODEGEN=codegen_x86.o
all: insthru
else
$(warning architecture $(ARCH) not supported.)
all:
endif

insthru: insthru.o $(CODEGEN)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean distclean

clean:
	rm -f *.o

distclean: clean
	rm -f insthru
