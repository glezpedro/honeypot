#!/usr/bin/env bash
set -euo pipefail

COWRIE_HOME=/opt/cowrie
COWRIE_USER=cowrie

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

# copytruncate: evita reiniciar Cowrie, el descriptor abierto sigue valido.
cat > /etc/logrotate.d/cowrie <<CONF
${COWRIE_HOME}/var/log/cowrie/cowrie.json
${COWRIE_HOME}/var/log/cowrie/cowrie.log
{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su ${COWRIE_USER} ${COWRIE_USER}
    create 0644 ${COWRIE_USER} ${COWRIE_USER}
}
CONF

cat > /etc/cron.daily/cowrie-disk-check <<'CHECK'
#!/bin/sh
USED=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [ "$USED" -gt 80 ]; then
  logger -t cowrie-disk "disco al ${USED}%"
fi
CHECK
chmod +x /etc/cron.daily/cowrie-disk-check
