# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
CC=cc
ECFLAGS=-Wall -pedantic -std=c99
CFLAGS=${ECFLAGS} -fPIC -DPIC -Os

BTMP=./bin/

TRG_DCPP=${HOME}/.purple/plugins/dcpp.so
BIN_DCPP=${BTMP}/dcpp.so${ENDING}
CFLAGS_DCPP=$(shell pkg-config --cflags --libs purple glib-2.0) -shared
TRG_DCPPD=./dcppd
BIN_DCPPD=${BTMP}/dcppd${ENDING}
CFLAGS_DCPPD=-lev

BIN=${BTMP}
BIN+=${BIN_DCPP}
BIN+=${BIN_DCPPD}

.PHONY: build clean

all:
	make CFLAGS="${CFLAGS}" ENDING=".release" build

debug:
	make CFLAGS="${CFLAGS} -g -DDEBUG" ENDING=".debug" build

build: ${BIN}
	cp -f ${BIN_DCPP} ${TRG_DCPP}
	cp -f ${BIN_DCPPD} ${TRG_DCPPD}

clean:
	rm -rf ${BIN}

${BTMP}:
	mkdir -p $@

${BIN_DCPP}: dcpp.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPP} $^

${BIN_DCPPD}: dcppd.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPPD} $^

