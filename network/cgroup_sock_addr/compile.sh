#!/bin/bash

clang -O2 -target bpf -c tcp_nat.c -o tcp_nat.o 2>/dev/null || clang -I/usr/include/x86_64-linux-gnu -O2 -target bpf -c tcp_nat.c -o tcp_nat.o