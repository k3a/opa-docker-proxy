#!/usr/bin/env bash
# Block Docker containers from reaching local LAN ranges.
# Usage: docker-lan-block.sh [clear]
#   (no argument)  apply the rules
#   clear          remove every rule this script added (matched by its "lan-block:"
#                  comment) from DOCKER-USER and INPUT, v4 and v6. Other rules, e.g.
#                  Docker's own, are left alone (so this is not a plain `iptables -F`).
# Idempotent: creates DOCKER-USER if missing, adds each rule only if absent.
# Config (override in /etc/default/docker-lan-block):
#   LAN_V4="192.168.0.0/16 10.0.0.0/8"   destinations to block (IPv4)
#   LAN_V6=""                            destinations to block (IPv6), e.g. "fd00::/8 fe80::/10"
#   ALLOW_V4=""                          exceptions, "ip[:proto:port]" e.g. "192.168.1.53:udp:53"
#   ALLOW_V6=""                          same for IPv6, e.g. "fd00::53:udp:53" or a bare "fd00::53"
#   ALLOW_DNS=auto                       DNS servers containers may use even if they are in a
#                                        blocked range (tcp+udp port 53). "auto" = nameservers
#                                        from /etc/resolv.conf and systemd-resolved's
#                                        /run/systemd/resolve/resolv.conf (loopback ignored);
#                                        a list of IPs, e.g. "192.168.0.1 fd00::1"; "" = none.
#                                        Needed when the host resolver is a LAN address
#                                        (Docker's embedded DNS queries it from the container).
#   IFACES="docker0 br+"                 container-side input interfaces
#   AUTO_DETECT=1                        1 = also block on-link subnets found via `ip route`
#                                        (added to LAN_V4/LAN_V6); 0 = static lists only
#   AUTO_EXCLUDE_DEV="docker* veth*"     interfaces (globs) ignored by detection;
#                                        IFACES are always ignored too
#   BLOCK_HOST=1                         1 = also block NEW container->host connections (INPUT),
#                                        i.e. containers cannot reach services on the host itself
#                                        (bridge gateway IP, host LAN IP); ALLOW_* exceptions
#                                        with a protocol/port also apply to the host. 0 = allow
#   ISOLATE_DEFAULT_BRIDGE=1             1 = containers on the default bridge cannot reach
#                                        each other (drops DEFAULT_BRIDGE -> DEFAULT_BRIDGE)
#   DEFAULT_BRIDGE=docker0               name of the default bridge
#                                        (isolation needs br_netfilter, which the script loads
#                                        and enables via sysctl when ISOLATE_DEFAULT_BRIDGE=1)
#
# Note: docker's default-address-pools (172.16.0.0/12) lie inside the default LAN_V4;
# same-bridge traffic is exempted from the LAN drops, see below.
#
# Container <-> container behaviour:
#   - containers started with no special config (default bridge, docker0) can NOT
#     reach each other (ISOLATE_DEFAULT_BRIDGE=1). Equivalent without iptables:
#     "icc": false in /etc/docker/daemon.json (affects docker0 only). Per-network ICC
#     cannot be used because the proxy denies the network options that would set it.
#   - containers in the same user-defined bridge (br-xxxx, e.g. docker compose's
#     "<project>_default") CAN reach each other: bridge-to-bridge traffic (-i br+ -o br+)
#     is RETURNed before the LAN drops, so same-bridge traffic passes even
#     though Docker's address pools lie inside LAN_V4 (172.16.0.0/12).
#   - different user-defined bridges stay isolated by Docker itself (DOCKER-ISOLATION
#     chains, evaluated after DOCKER-USER).
# Test: two `docker run -d alpine sleep 1d` cannot ping each other; two services of one
# compose project can; neither can reach the LAN.
set -euo pipefail

LAN_V4="192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 100.64.0.0/10 169.254.0.0/16 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24"
LAN_V6="fe80::/10 fc00::/7"
ALLOW_V4=""
ALLOW_V6=""
ALLOW_DNS="auto"
IFACES="docker0 br+"
BLOCK_HOST=1
ISOLATE_DEFAULT_BRIDGE=1
DEFAULT_BRIDGE="docker0"
AUTO_DETECT=1
AUTO_EXCLUDE_DEV="docker* veth*"
# shellcheck disable=SC1091
[[ -r /etc/default/docker-lan-block ]] && . /etc/default/docker-lan-block

# detect_subnets FAMILY : print connected (on-link) subnets from `ip route`,
# skipping interfaces matching AUTO_EXCLUDE_DEV / IFACES (docker's own bridges,
# otherwise container<->container traffic would get blocked).
detect_subnets() {
  local fam=$1 line net dev pat skip
  local -a pats=()
  read -ra pats <<<"$AUTO_EXCLUDE_DEV ${IFACES//+/*}"
  while read -r line; do
    set -- $line
    net=$1; dev=""
    while (($#)); do [[ $1 == dev ]] && { dev=$2; break; }; shift; done
    [[ $net == */* && -n $dev ]] || continue
    skip=0
    for pat in "${pats[@]}"; do
      # shellcheck disable=SC2254
      case $dev in $pat) skip=1; break;; esac
    done
    ((skip)) || echo "$net $dev"
  done < <(ip "-$fam" -o route show scope link 2>/dev/null; \
           [[ $fam == 6 ]] && ip -6 -o route show proto kernel 2>/dev/null || true)
}

# SRC["<family>:<net>"] = where the entry came from; used as the iptables rule comment.
declare -A SRC=()
for n in $LAN_V4; do SRC["4:$n"]="config"; done
for n in $LAN_V6; do SRC["6:$n"]="config"; done

# add_detected FAMILY : append detected subnets not already configured
add_detected() {
  local fam=$1 net dev
  while read -r net dev; do
    [[ $fam == 6 && $net == fe80:* ]] && continue   # covered by fe80::/10
    [[ -n ${SRC["$fam:$net"]:-} ]] && continue      # config wins / first interface wins
    SRC["$fam:$net"]="auto $dev"
    if [[ $fam == 4 ]]; then LAN_V4+=" $net"; else LAN_V6+=" $net"; fi
  done < <(detect_subnets "$fam" | sort -u)
}

if [[ $AUTO_DETECT == 1 ]] && command -v ip >/dev/null; then
  add_detected 4
  add_detected 6
fi

# Allow DNS servers (see ALLOW_DNS) by appending tcp+udp/53 exceptions.
dns_servers=""
if [[ $ALLOW_DNS == auto ]]; then
  for f in /etc/resolv.conf /run/systemd/resolve/resolv.conf; do
    [[ -r $f ]] || continue
    while read -r key val _; do
      [[ $key == nameserver ]] || continue
      dns_servers+=" ${val%%%*}"   # drop IPv6 zone id (fe80::1%eth0)
    done <"$f"
  done
else
  dns_servers=$ALLOW_DNS
fi
for ns in $dns_servers; do
  [[ $ns == 127.* || $ns == ::1 ]] && continue
  if [[ $ns == *:* ]]; then entries=ALLOW_V6; else entries=ALLOW_V4; fi
  for proto in udp tcp; do
    [[ " ${!entries} " == *" $ns:$proto:53 "* ]] || printf -v "$entries" '%s %s' "${!entries}" "$ns:$proto:53"
  done
done

# parse_allow ENTRY : set ip/proto/port from "ip", "ip:proto:port" (IPv6-safe)
parse_allow() {
  proto="" port=""
  if [[ $1 =~ ^(.+):(tcp|udp):([0-9]+)$ ]]; then
    ip=${BASH_REMATCH[1]} proto=${BASH_REMATCH[2]} port=${BASH_REMATCH[3]}
  else
    ip=$1
  fi
}

# ensure CMD CHAIN POS RULE...  : insert RULE at position POS unless already present
ensure() {
  local cmd=$1 chain=$2 pos=$3; shift 3
  "$cmd" -C "$chain" "$@" 2>/dev/null || "$cmd" -I "$chain" "$pos" "$@"
}

prepare_chain() {
  local cmd=$1
  "$cmd" -n -L DOCKER-USER >/dev/null 2>&1 || {
    "$cmd" -N DOCKER-USER
    "$cmd" -A DOCKER-USER -j RETURN
  }
  # Make sure FORWARD consults it (Docker adds this too, but only once it runs).
  "$cmd" -C FORWARD -j DOCKER-USER 2>/dev/null || "$cmd" -I FORWARD 1 -j DOCKER-USER
}

apply() {
  local cmd=$1 lan=$2 allow=$3
  command -v "$cmd" >/dev/null || return 0
  [[ -z $lan && $BLOCK_HOST != 1 && $ISOLATE_DEFAULT_BRIDGE != 1 ]] && return 0
  prepare_chain "$cmd"

  # Inserted at position 1 in reverse priority, so final order is:
  #   1 ESTABLISHED  2 ALLOW exceptions  3 DROP default-bridge<->default-bridge
  #   4 RETURN bridge->bridge  5 DROP lan   (then Docker's own rules)
  local i o t net a ip proto port fam=4
  [[ $cmd == ip6tables ]] && fam=6

  # 5: LAN drops (iptables allows only one -o per rule, so same-bridge traffic is
  # exempted by the RETURN rules below instead of by "! -o").
  for i in $IFACES; do
    for net in $lan; do
      ensure "$cmd" DOCKER-USER 1 -i "$i" -d "$net" \
        -m comment --comment "lan-block: drop LAN (${SRC["$fam:$net"]})" -j DROP
    done
  done

  # 4: traffic between container bridges (same bridge, e.g. compose networks, or
  # bridge to bridge) skips the LAN drops and goes on to Docker's own rules, which
  # accept same-bridge traffic and isolate different user-defined bridges.
  for i in $IFACES; do
    for o in $IFACES; do
      ensure "$cmd" DOCKER-USER 1 -i "$i" -o "$o" \
        -m comment --comment "lan-block: allow container bridge traffic" -j RETURN
    done
  done

  # 3: default bridge containers cannot talk to each other.
  if [[ $ISOLATE_DEFAULT_BRIDGE == 1 ]]; then
    ensure "$cmd" DOCKER-USER 1 -i "$DEFAULT_BRIDGE" -o "$DEFAULT_BRIDGE" \
      -m comment --comment "lan-block: drop default bridge container<->container" -j DROP
  fi

  for i in $IFACES; do
    for a in $allow; do
      parse_allow "$a"
      if [[ -n ${proto:-} ]]; then
        ensure "$cmd" DOCKER-USER 1 -i "$i" -d "$ip" -p "$proto" --dport "$port" \
          -m comment --comment "lan-block: allow exception (config)" -j ACCEPT
      else
        ensure "$cmd" DOCKER-USER 1 -i "$i" -d "$ip" \
          -m comment --comment "lan-block: allow exception (config)" -j ACCEPT
      fi
    done
  done
  ensure "$cmd" DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED \
    -m comment --comment "lan-block: allow established" -j ACCEPT

  if [[ $BLOCK_HOST == 1 ]]; then
    # Final INPUT order (inserted in reverse): ND accepts, exceptions, then the DROP.
    for i in $IFACES; do
      ensure "$cmd" INPUT 1 -i "$i" -m conntrack --ctstate NEW \
        -m comment --comment "lan-block: drop container->host (BLOCK_HOST)" -j DROP
      for a in $allow; do   # exceptions for host-bound traffic (same syntax)
        parse_allow "$a"
        if [[ -n ${proto:-} ]]; then
          ensure "$cmd" INPUT 1 -i "$i" -d "$ip" -p "$proto" --dport "$port" \
            -m comment --comment "lan-block: allow host exception (config)" -j ACCEPT
        fi
      done
      if [[ $fam == 6 ]]; then   # IPv6 neighbour/router discovery must keep working
        for t in neighbour-solicitation neighbour-advertisement router-solicitation; do
          ensure "$cmd" INPUT 1 -i "$i" -p ipv6-icmp --icmpv6-type "$t" \
            -m comment --comment "lan-block: allow IPv6 discovery" -j ACCEPT
        done
      fi
    done
  fi
}

# clear_rules CMD : delete all rules carrying the "lan-block:" comment
clear_rules() {
  local cmd=$1 chain n
  command -v "$cmd" >/dev/null || return 0
  for chain in DOCKER-USER INPUT; do
    "$cmd" -n -L "$chain" >/dev/null 2>&1 || continue
    # highest line number first so earlier numbers stay valid while deleting
    while read -r n; do
      "$cmd" -D "$chain" "$n"
    done < <("$cmd" -n -L "$chain" --line-numbers | awk '/lan-block:/ {print $1}' | sort -rn)
  done
}

case "${1:-}" in
  "") ;;
  clear)
    clear_rules iptables
    clear_rules ip6tables
    exit 0 ;;
  *)
    echo "usage: ${0##*/} [clear]" >&2
    exit 2 ;;
esac

# Traffic between two containers on the same bridge is switched by the bridge and
# only passes through iptables (FORWARD / DOCKER-USER) when br_netfilter is loaded
# and bridge-nf-call-iptables=1. Without it the default-bridge isolation rule below
# never sees a packet and does nothing. ("clear" leaves the module/sysctls alone.)
if [[ $ISOLATE_DEFAULT_BRIDGE == 1 ]]; then
  modprobe br_netfilter 2>/dev/null || echo "warning: cannot load br_netfilter; default bridge isolation will not work" >&2
  for k in net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables; do
    sysctl -qw "$k=1" 2>/dev/null || echo "warning: cannot set $k=1; default bridge isolation may not work" >&2
  done
fi

apply iptables  "$LAN_V4" "$ALLOW_V4"
apply ip6tables "$LAN_V6" "$ALLOW_V6"
