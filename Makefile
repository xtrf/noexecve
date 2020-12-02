CC = gcc
DEFINES = -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS = -std=gnu99 -g -O2 -fstack-protector-strong -Wall -W

libnoexecve.so : noexecve.c
	$(CC) $(CFLAGS) $(DEFINES) -fpic -shared -o $@ $<
