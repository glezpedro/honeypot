#!/usr/bin/env bash
set -euo pipefail

COWRIE_HOME=/opt/cowrie
COWRIE_USER=cowrie
LOG_DIR="${COWRIE_HOME}/var/log/cowrie"
KEEP_DAYS=30

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

# Cowrie rota cowrie.json por su cuenta con DailyLogFile y eso no se desactiva.
# Una configuracion de logrotate sobre el mismo fichero compite con ella a las
# 02:00 y unos dias gana una y otros la otra.
if [[ -f /etc/logrotate.d/cowrie ]]; then
  rm -f /etc/logrotate.d/cowrie
  echo "==> Retirada la configuracion de logrotate que competia con Cowrie"
fi
rm -f /etc/cron.daily/cowrie-disk-check

cat > /etc/cron.daily/cowrie-logs <<CRON
#!/bin/sh
find ${LOG_DIR} -name 'cowrie.json.????-??-??' -size 0 -delete
find ${LOG_DIR} -name 'cowrie.json.????-??-??' -mtime +1 -exec gzip -9 {} \;
find ${LOG_DIR} -name 'cowrie.json.*.gz' -mtime +${KEEP_DAYS} -delete

USED=\$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [ "\$USED" -gt 80 ]; then
  logger -t cowrie-disk "disco al \${USED}%"
fi
CRON
chmod +x /etc/cron.daily/cowrie-logs
chown -R "${COWRIE_USER}:${COWRIE_USER}" "${LOG_DIR}"

/etc/cron.daily/cowrie-logs
echo "==> Rotacion a cargo de Cowrie; compresion y purga a ${KEEP_DAYS} dias"
ls -la "${LOG_DIR}" | tail -5
