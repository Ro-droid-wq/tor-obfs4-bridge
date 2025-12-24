#!/usr/bin/env bash
set -euo pipefail

# ====== SETTINGS ======
BRIDGE_PORT="${BRIDGE_PORT:-8443}"
ORPORT="${ORPORT:-9001}"
TORRC_PATH="/etc/tor/torrc"
BRIDGELINE_PATH="/var/lib/tor/pt_state/obfs4_bridgeline.txt"
TOR_USER="debian-tor"
# ======================

log() { echo -e "[+] $*"; }
err() { echo -e "[!] $*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
  err "Run as root: sudo bash $0"
  exit 1
fi

log "Updating apt and installing dependencies..."
apt-get update -y
apt-get install -y tor obfs4proxy ufw

# ---- Ensure SSH stays reachable ----
log "Configuring UFW to keep SSH access..."
ufw allow OpenSSH >/dev/null || true
ufw allow 22/tcp >/dev/null || true

# Enable UFW if not enabled
if ! ufw status | grep -q "Status: active"; then
  log "Enabling UFW (SSH already allowed)..."
  ufw --force enable >/dev/null
fi

log "Opening bridge port ${BRIDGE_PORT}/tcp in UFW..."
ufw allow "${BRIDGE_PORT}/tcp" >/dev/null || true
ufw reload >/dev/null || true

# ---- Write torrc ----
log "Writing ${TORRC_PATH}..."
cat > "${TORRC_PATH}" <<EOF
############ PRIVATE TOR BRIDGE (obfs4) ############

RunAsDaemon 1
SocksPort 0

BridgeRelay 1
ORPort ${ORPORT}

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:${BRIDGE_PORT}

ExtORPort auto
PublishServerDescriptor 0

DataDirectory /var/lib/tor
Log notice syslog
EOF

# ---- Multi-instance: prefer tor@default ----
log "Setting up tor@default instance (Ubuntu 22.04 multi-instance)..."
mkdir -p /etc/tor/instances.d
touch /etc/tor/instances.d/default

# Stop/disable master tor.service to avoid confusion
systemctl stop tor >/dev/null 2>&1 || true
systemctl disable tor >/dev/null 2>&1 || true

log "Starting tor@default..."
systemctl daemon-reload
systemctl enable --now tor@default

# ---- Wait for bridgeline ----
log "Waiting for bridge line to be generated..."
timeout_sec=120
interval=2
elapsed=0

while [[ ! -s "${BRIDGELINE_PATH}" ]]; do
  sleep "${interval}"
  elapsed=$((elapsed + interval))
  if (( elapsed >= timeout_sec )); then
    err "Timed out waiting for ${BRIDGELINE_PATH}"
    err "Check logs: sudo journalctl -u tor@default -n 200 --no-pager"
    err "Check port: sudo ss -lntp | grep :${BRIDGE_PORT}"
    exit 1
  fi
done

log "Bridge line found:"
echo "------------------------------------------------------------"
sudo -u "${TOR_USER}" cat "${BRIDGELINE_PATH}"
echo "------------------------------------------------------------"

log "Done."
log "IMPORTANT: also open TCP/${BRIDGE_PORT} in your VPS provider firewall panel if you use one."
