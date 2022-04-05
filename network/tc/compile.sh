#!/bin/bash

set -e

clang -O2 -target bpf -c udp_nat.c -o tc_udp_nat.o 2>/dev/null || clang -I/usr/include/x86_64-linux-gnu -O2 -target bpf -c udp_nat.c -o tc_udp_nat.o
