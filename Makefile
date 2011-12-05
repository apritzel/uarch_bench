SH=/bin/sh
CC=gcc
CFLAGS=-Wall -O

all: insthru

insthru: insthru.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f insthru
