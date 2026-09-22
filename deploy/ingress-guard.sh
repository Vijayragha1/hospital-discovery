#!/bin/sh
# The guard owns the web network namespace. Caddy starts only after this is healthy.
# It has no source mounts or application secrets; only this helper has NET_ADMIN.
set -eu
umask 022
rm -f /run/ingress/ready /run/ingress/upstream.caddy

# Resolve the one permitted backend before dropping DNS and all other new egress.
# The API is on an internal Docker network; no external hostname is consulted.
api_ip="$(getent hosts api | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]/ {print $1; exit}')"
case "$api_ip" in
  10.*|172.*|192.168.*) ;;
  *) echo 'Internal API address was unavailable; ingress remains disabled.' >&2; exit 1 ;;
esac

# A failure at any point prevents the ready marker and therefore prevents Caddy startup.
iptables -w -P OUTPUT DROP
iptables -w -P INPUT DROP
iptables -w -P FORWARD DROP
iptables -w -F OUTPUT
iptables -w -F INPUT
iptables -w -F FORWARD
iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A OUTPUT -d "$api_ip/32" -p tcp --dport 8765 -m conntrack --ctstate NEW -j ACCEPT
iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A INPUT -p tcp --dport 8443 -m conntrack --ctstate NEW -j ACCEPT

# No IPv6 egress or ingress is required by this IPv4-only pilot deployment.
ip6tables -w -P OUTPUT DROP
ip6tables -w -P INPUT DROP
ip6tables -w -P FORWARD DROP
ip6tables -w -F OUTPUT
ip6tables -w -F INPUT
ip6tables -w -F FORWARD

printf 'reverse_proxy %s:8765\n' "$api_ip" > /run/ingress/upstream.caddy
touch /run/ingress/ready
trap 'exit 0' TERM INT
while :; do
  sleep 3600 &
  wait "$!"
done
