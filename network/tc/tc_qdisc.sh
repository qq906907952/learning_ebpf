#!/bin/bash

#reference https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/



set -e

tc qdisc delete dev $1 clsact 2>/dev/null || echo

tc qdisc add dev  $1 clsact # offload: tc qdisc delete dev lo  clsact
tc filter add dev $1 egress bpf direct-action obj tc_udp_nat.o sec .egress # show:  tc filter show dev lo ingress
tc filter add dev $1 ingress bpf direct-action obj tc_udp_nat.o sec .ingress # show:  tc filter show dev lo egress
