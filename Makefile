# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
CC=cc
ECFLAGS=-Wall -pedantic -std=c99
CFLAGS=${ECFLAGS} -fPIC -DPIC -Os
BIN_DCPP=${HOME}/.purple/plugins/dcpp.so
CFLAGS_DCPP=$(shell pkg-config --cflags --libs purple glib-2.0) -shared
BIN_DCPPD=./dcppd
CFLAGS_DCPPD=-lev

BIN=
BIN+=${BIN_DCPP}
BIN+=${BIN_DCPPD}

.PHONY: build clean

all:
	make CFLAGS="${CFLAGS}" build

debug:
	make CFLAGS="${CFLAGS} -g -DDEBUG" build

build: ${BIN}

clean:
	rm -rf ${BIN}

${BIN_DCPP}: dcpp.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPP} $^

${BIN_DCPPD}: dcppd.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPPD} $^

