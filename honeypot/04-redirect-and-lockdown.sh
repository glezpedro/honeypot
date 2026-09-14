#!/usr/bin/env bash
set -euo pipefail

COWRIE_USER=cowrie
COWRIE_PORT=2222

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

if ss -tlnp 2>/dev/null | grep sshd | grep -q ':22 '; then
  echo "sshd sigue en el 22. Ejecuta antes 02-close-admin-22.sh." >&2
  exit 1
fi

command -v netfilter-persistent >/dev/null 2>&1 || \
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent

iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "${COWRIE_PORT}" 2>/dev/null || \
  iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "${COWRIE_PORT}"

iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT

COWRIE_UID="$(id -u "${COWRIE_USER}")"

# Solo NEW: un REJECT a secas bloquearia tambien las respuestas del honeypot.
iptables -C OUTPUT -m owner --uid-owner "${COWRIE_UID}" -o lo -j ACCEPT 2>/dev/null || \
  iptables -A OUTPUT -m owner --uid-owner "${COWRIE_UID}" -o lo -j ACCEPT
iptables -C OUTPUT -m owner --uid-owner "${COWRIE_UID}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A OUTPUT -m owner --uid-owner "${COWRIE_UID}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C OUTPUT -m owner --uid-owner "${COWRIE_UID}" -m conntrack --ctstate NEW -j REJECT 2>/dev/null || \
  iptables -A OUTPUT -m owner --uid-owner "${COWRIE_UID}" -m conntrack --ctstate NEW -j REJECT

netfilter-persistent save >/dev/null
