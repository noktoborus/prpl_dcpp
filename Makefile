# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
CC=cc
CP=cp -rf
ECFLAGS=-Wall -pedantic -std=c99 -D_POSIX_SOURCE
CFLAGS=${ECFLAGS} -fPIC -DPIC -Os

BTMP=./bin/

# DCPP
TRG_DCPP=${HOME}/.purple/plugins/dcpp.so
BIN_DCPP=${BTMP}/dcpp.so${ENDING}
CFLAGS_DCPP=$(shell pkg-config --cflags --libs purple glib-2.0) -shared
# DCPPD
TRG_DCPPD=./dcppd
BIN_DCPPD=${BTMP}/dcppd${ENDING}
CFLAGS_DCPPD=-lev
# DCPPS5D
TRG_DCPPD_S5S=./dcppd_S5s
BIN_DCPPD_S5S=${BTMP}/dcppd_S5s${ENDING}
CFLAGS_DCPPD_S5S=-lev

TRG=${BTMP}
TRG+=${TRG_DCPP}
TRG+=${TRG_DCPPD}
TRG+=${TRG_DCPPD_S5S}

.PHONY: build clean

all:
	make CFLAGS="${CFLAGS}" ENDING=".release" install

debug:
	make CFLAGS="${CFLAGS} -g -DDEBUG" ENDING=".debug" install

install: ${TRG}

clean:
	rm -rf ${TRG} ${BTMP}

${BTMP}:
	mkdir -p $@

${BIN_DCPP}: dcpp.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPP} $^

${TRG_DCPP}: ${BIN_DCPP}
	${CP} $^ $@

${BIN_DCPPD}: dcppd.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPPD} $^

${TRG_DCPPD}: ${BIN_DCPPD}
	${CP} $^ $@

${BIN_DCPPD_S5S}: dcppd_S5s.c
	${CC} -o $@ ${CFLAGS} ${CFLAGS_DCPPD_S5S} $^

${TRG_DCPPD_S5S}: ${BIN_DCPPD_S5S}
	${CP} $^ $@

