#!/usr/bin/env bash
set -eux
######################################################
# configs
######################################################

IN=main.go
OUT=build/bsha256

GOARCH=amd64

######################################################
# build
######################################################

if ! test -e "$IN"; then
	echo "$IN not exists. exiting..."
	exit 1
fi

if ! test -d build/; then
	mkdir build/
fi

if test -e "$OUT"; then
	rm -f "$OUT"
fi

go build \
	-gcflags=-m \
	-o "$OUT" \
	-ldflags='-s -w -extldflags "-O3 -match=native"' \
	-trimpath \
	"$IN"
