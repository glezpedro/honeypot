#!/usr/bin/env bash
set -euo pipefail

COWRIE_USER=cowrie
COWRIE_HOME=/opt/cowrie
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Requiere root." >&2; exit 1; }

apt-get update -qq
apt-get install -y -qq git python3-venv python3-dev libssl-dev libffi-dev build-essential

id -u "${COWRIE_USER}" >/dev/null 2>&1 || \
  adduser --disabled-password --gecos "" --shell /usr/sbin/nologin "${COWRIE_USER}"

if [[ ! -d "${COWRIE_HOME}/.git" ]]; then
  git clone --quiet https://github.com/cowrie/cowrie.git "${COWRIE_HOME}"
  chown -R "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}"
fi

# 'pip install -e .' ademas de requirements: registra el plugin de twisted.
sudo -u "${COWRIE_USER}" bash <<VENV
set -euo pipefail
cd "${COWRIE_HOME}"
[[ -d cowrie-env ]] || python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
pip install --quiet -e .
VENV

install -o "${COWRIE_USER}" -g "${COWRIE_USER}" -m 0644 "${HERE}/cowrie.cfg" "${COWRIE_HOME}/etc/cowrie.cfg"
install -o "${COWRIE_USER}" -g "${COWRIE_USER}" -m 0644 "${HERE}/userdb.txt" "${COWRIE_HOME}/etc/userdb.txt"

cat > /etc/systemd/system/cowrie.service <<UNIT
[Unit]
Description=Cowrie SSH honeypot
After=network.target

[Service]
Type=simple
User=${COWRIE_USER}
Group=${COWRIE_USER}
WorkingDirectory=${COWRIE_HOME}
Environment=PYTHONPATH=${COWRIE_HOME}/src
ExecStart=${COWRIE_HOME}/cowrie-env/bin/twistd -n -l- --umask=0022 --pidfile= cowrie
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${COWRIE_HOME}/var

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --quiet cowrie
systemctl restart cowrie
sleep 3

if ! ss -tln | grep -q ':2222'; then
  echo "Cowrie no escucha en el 2222. journalctl -u cowrie -n 50 --no-pager" >&2
  exit 1
fi
