#!/bin/bash
# Recreates Docker's firewall rules when another firewall flushed them.
#
# `csf -r` (and other firewall restarts) flush every iptables chain,
# including Docker's own DOCKER chains. Docker only creates them when it
# starts, so until then a container cannot publish a port and a rebuilt
# portal fails with "iptables: No chain/target/match by that name". The
# portal setup calls this from CSF's csfpost.sh and before starting the
# containers. Docker is restarted only when its chains are missing.

command -v iptables >/dev/null 2>&1 || exit 0
command -v docker >/dev/null 2>&1 || exit 0
systemctl is-active -q docker || exit 0
# Docker's nftables firewall backend keeps no iptables chains.
case "$(docker info -f '{{with .FirewallBackend}}{{.Driver}}{{end}}' 2>/dev/null)" in
  *nftables*) exit 0 ;;
esac
iptables -w -t nat -n -L DOCKER >/dev/null 2>&1 && exit 0

logger -t xpguard "Docker's firewall rules were flushed; restarting Docker to recreate them" 2>/dev/null || true
systemctl restart docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done
exit 1
