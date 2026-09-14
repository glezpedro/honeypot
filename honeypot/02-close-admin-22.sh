#!/usr/bin/env bash
set -euo pipefail

ADMIN_PORT="${ADMIN_PORT:-54321}"

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

if [[ "$(echo "${SSH_CONNECTION:-}" | awk '{print $4}')" == "22" ]]; then
  echo "Conectado por el 22: verifica el ${ADMIN_PORT} primero. FORCE=1 para omitir." >&2
  [[ "${FORCE:-0}" == "1" ]] || exit 1
fi

printf 'Port %s\n' "${ADMIN_PORT}" > /etc/ssh/sshd_config.d/99-admin-port.conf
sshd -t
systemctl restart ssh

# Al pasar de socket a servicio, systemd pierde la pista del sshd del boot:
# sobrevive al restart y sigue en el 22.
MAIN_PID="$(systemctl show -p MainPID --value ssh 2>/dev/null || echo 0)"
for pid in $(ss -tlnp 2>/dev/null | grep ':22 ' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
  [[ "${pid}" == "${MAIN_PID}" ]] || kill "${pid}" 2>/dev/null || true
done
sleep 1

if ss -tln | grep -q ':22 '; then
  echo "Algo sigue escuchando en el 22:" >&2
  ss -tlnp | grep ':22 ' >&2
  exit 1
fi
