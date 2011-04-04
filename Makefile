# vim: ft=make ff=unix fenc=utf-8
# file: Makefile
CC=cc
LIBS=$(shell pkg-config --cflags --libs purple glib-2.0)
CFLAGS=-shared -fPIC -DPIC -Os
ECFLAGS=-g -Wall -pedantic -std=c99

all: dcpp.so
	cp -f $< ${HOME}/.purple/plugins

dcpp.so: dcpp.c
	${CC} -o $@ ${LIBS} ${CFLAGS} ${ECFLAGS} $^

