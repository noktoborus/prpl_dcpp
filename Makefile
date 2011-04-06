# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
CC=cc
LIBS=$(shell pkg-config --cflags --libs purple glib-2.0)
CFLAGS=-shared -fPIC -DPIC -Os
ECFLAGS=-Wall -pedantic -std=c99
BIN_DCPP=${HOME}/.purple/plugins/dcpp.so

.PHONY: all clean

all: ${BIN_DCPP}

debug:
	make CFLAGS="${CFLAGS} -g -DDEBUG" all

clean:
	rm -rf ${BIN_DCPP}

${BIN_DCPP}: dcpp.c
	${CC} -o $@ ${LIBS} ${CFLAGS} ${ECFLAGS} $^

