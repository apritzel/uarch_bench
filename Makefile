SH=/bin/sh
CC=gcc
CFLAGS=-Wall -O
LDFLAGS=

all: insthru

insthru: insthru.o codegen_x86.o
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f *.o insthru
