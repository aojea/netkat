#!/bin/bash
set -x

PROG=${PROG:-"filter.c"}
IFACE=${IFACE:-"docker0"}

# compile 
clang -target bpf -Wall -O2 -c ${PROG} -o test.o

tc qdisc add dev $IFACE clsact
tc filter add dev $IFACE ingress bpf direct-action obj test.o sec classifier
tc filter show dev $IFACE
# remove
# sudo tc qdisc del dev docker0 clsact

