#!/usr/bin/env bash
set -euo pipefail

ADMIN_PORT="${ADMIN_PORT:-54321}"

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

# En Ubuntu 24.04 sshd arranca por socket y el Port de sshd_config se ignora.
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
  systemctl disable --now ssh.socket
  systemctl enable ssh.service
fi

mkdir -p /etc/ssh/sshd_config.d
printf 'Port 22\nPort %s\n' "${ADMIN_PORT}" > /etc/ssh/sshd_config.d/99-admin-port.conf

command -v netfilter-persistent >/dev/null 2>&1 || \
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent

# -I y no -A: algunas imagenes traen un REJECT al final de INPUT.
iptables -C INPUT -p tcp --dport "${ADMIN_PORT}" -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --dport "${ADMIN_PORT}" -j ACCEPT
netfilter-persistent save >/dev/null

sshd -t
systemctl restart ssh

ss -tlnp | grep -E ":(22|${ADMIN_PORT})\b" || true
echo "Verifica el acceso por ${ADMIN_PORT} en otra sesion antes de ejecutar 02."
