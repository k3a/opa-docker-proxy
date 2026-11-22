#!/usr/bin/env bash
# Smoke test for docker-lan-block.sh. Needs a running Docker daemon and the rules applied
# (run docker-lan-block.sh as root first). Creates and removes containers named lbtest-*
# and networks lbtest-*, pulls alpine if missing. Does not need root itself.
#
# Usage: [EXPECT_BLOCK_HOST=0] test-docker-lan-block.sh [LAN_HOST]
#   EXPECT_BLOCK_HOST  1 (default) = containers must NOT reach host services (BLOCK_HOST=1);
#                      set 0 if you run the script with BLOCK_HOST=0.
#   LAN_HOST  an address on your LAN that answers ping from the host (default: first
#             default gateway). Skipped if none is found.
set -uo pipefail

IMG=alpine
PASS=0 FAIL=0 SKIP=0

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

# expect_ok DESC CMD...   /  expect_fail DESC CMD...
expect_ok()   { local d=$1; shift; if "$@" >/dev/null 2>&1; then green "PASS  $d"; ((PASS++)); else red "FAIL  $d (expected success)"; ((FAIL++)); fi; }
expect_fail() { local d=$1; shift; if "$@" >/dev/null 2>&1; then red "FAIL  $d (expected failure)"; ((FAIL++)); else green "PASS  $d"; ((PASS++)); fi; }
skip()        { echo "SKIP  $1"; ((SKIP++)); }

EXPECT_BLOCK_HOST=${EXPECT_BLOCK_HOST:-1}
LISTENER_PID=""
LISTENER_DIR=""

cleanup() {
  [[ -n $LISTENER_PID ]] && kill "$LISTENER_PID" >/dev/null 2>&1
  [[ -n $LISTENER_DIR ]] && rm -rf "$LISTENER_DIR"
  docker rm -f lbtest-a lbtest-b lbtest-c lbtest-d lbtest-e >/dev/null 2>&1
  docker network rm lbtest-n1 lbtest-n2 >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

ping_from() { docker exec "$1" ping -c1 -W2 "$2"; }
ip_on()     { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }

echo "== prerequisites"
docker info >/dev/null 2>&1 || { red "docker not reachable"; exit 2; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker pull -q "$IMG" >/dev/null || { red "cannot pull $IMG"; exit 2; }
# Informational only: the behaviour checks below are the real proof. br_netfilter may be
# built in (not in lsmod) and the sysctl is not readable in every environment.
BNF=/proc/sys/net/bridge/bridge-nf-call-iptables
if [[ -r $BNF && $(cat "$BNF") == 1 ]]; then
  echo "INFO  bridge-nf-call-iptables=1"
else
  echo "INFO  bridge-nf-call-iptables not 1/readable; if the default bridge isolation test fails, run the lan-block script as root (it loads br_netfilter)"
fi

echo "== setup"
docker network create lbtest-n1 >/dev/null
docker network create lbtest-n2 >/dev/null
docker run -d --name lbtest-a "$IMG" sleep 600 >/dev/null     # default bridge
docker run -d --name lbtest-b "$IMG" sleep 600 >/dev/null     # default bridge
docker run -d --name lbtest-c --network lbtest-n1 "$IMG" sleep 600 >/dev/null
docker run -d --name lbtest-d --network lbtest-n1 "$IMG" sleep 600 >/dev/null
docker run -d --name lbtest-e --network lbtest-n2 "$IMG" sleep 600 >/dev/null

A_IP=$(ip_on lbtest-a bridge)
C_IP=$(ip_on lbtest-c lbtest-n1)

echo "== container <-> container"
expect_fail "default bridge: b cannot reach a ($A_IP)"           ping_from lbtest-b "$A_IP"
expect_ok   "user network:   d reaches c by IP ($C_IP)"          ping_from lbtest-d "$C_IP"
expect_ok   "user network:   d reaches c by name"                ping_from lbtest-d lbtest-c
expect_fail "other network:  e (n2) cannot reach c (n1)"         ping_from lbtest-e "$C_IP"
expect_fail "default bridge -> user network: b cannot reach c"   ping_from lbtest-b "$C_IP"

echo "== LAN / internet / DNS"
LAN_HOST=${1:-$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')}
if [[ -n $LAN_HOST ]]; then
  expect_fail "default bridge cannot reach LAN host $LAN_HOST"   ping_from lbtest-b "$LAN_HOST"
  expect_fail "user network cannot reach LAN host $LAN_HOST"     ping_from lbtest-d "$LAN_HOST"
else
  skip "no LAN host (pass one as the first argument)"
fi
expect_ok "internet reachable (1.1.1.1) from default bridge"     ping_from lbtest-b 1.1.1.1
expect_ok "internet reachable (1.1.1.1) from user network"       ping_from lbtest-d 1.1.1.1
expect_ok "DNS works on default bridge"                          docker exec lbtest-b nslookup example.com
expect_ok "DNS works on user network"                            docker exec lbtest-d nslookup example.com

echo "== container -> host (BLOCK_HOST expected: $EXPECT_BLOCK_HOST)"
if command -v python3 >/dev/null; then
  LISTENER_DIR=$(mktemp -d)
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')
  (cd "$LISTENER_DIR" && exec python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1) &
  LISTENER_PID=$!
  sleep 1
  host_get() { docker exec "$1" wget -q -T2 -O /dev/null "http://$2:$PORT/"; }
  expect_ok "control: host listener works locally (port $PORT)" bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT"
  HOST_LAN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')
  GW_DEF=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
  GW_N1=$(docker network inspect lbtest-n1 -f '{{(index .IPAM.Config 0).Gateway}}')
  if [[ $EXPECT_BLOCK_HOST == 1 ]]; then hostcheck=expect_fail; verb="cannot"; else hostcheck=expect_ok; verb="can"; fi
  $hostcheck "default bridge $verb reach host via gateway $GW_DEF"   host_get lbtest-b "$GW_DEF"
  $hostcheck "user network $verb reach host via gateway $GW_N1"      host_get lbtest-d "$GW_N1"
  if [[ -n $HOST_LAN_IP ]]; then
    $hostcheck "default bridge $verb reach host LAN IP $HOST_LAN_IP" host_get lbtest-b "$HOST_LAN_IP"
    $hostcheck "user network $verb reach host LAN IP $HOST_LAN_IP"    host_get lbtest-d "$HOST_LAN_IP"
  else
    skip "host LAN IP not found"
  fi
else
  skip "python3 not available for the host listener"
fi

echo
echo "passed=$PASS failed=$FAIL skipped=$SKIP"
if ((FAIL)); then
  echo "hint: sudo iptables -L DOCKER-USER -v -n --line-numbers   (look at packet counters)"
  exit 1
fi
