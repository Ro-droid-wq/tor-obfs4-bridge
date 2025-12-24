#!/usr/bin/env bash
set -euo pipefail

BRIDGE_PORT="${BRIDGE_PORT:-8443}"
ORPORT="${ORPORT:-9001}"
TIMEOUT_SEC="${TIMEOUT_SEC:-240}"

TORRC_PATH="/etc/tor/torrc"
TOR_USER="debian-tor"
DATA_DIR="/var/lib/tor"
PT_STATE_DIR="${DATA_DIR}/pt_state"
BRIDGELINE_TXT="${PT_STATE_DIR}/obfs4_bridgeline.txt"
BRIDGESTATE_JSON="${PT_STATE_DIR}/obfs4_state.json"
FINGERPRINT_FILE="${DATA_DIR}/fingerprint"

log(){ echo "[+] $*"; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[x] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"

log "Installing packages..."
apt-get update -y
apt-get install -y tor obfs4proxy ufw curl

log "Configuring UFW (keep SSH)..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 22/tcp >/dev/null 2>&1 || true
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable >/dev/null
fi
ufw allow "${BRIDGE_PORT}/tcp" >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

PUBLIC_IP="$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
[[ -n "${PUBLIC_IP}" ]] || die "Could not detect public IP (api.ipify.org blocked)."

log "Writing ${TORRC_PATH}..."
cat > "${TORRC_PATH}" <<EOF
############ PRIVATE TOR BRIDGE (obfs4) ############

RunAsDaemon 1
SocksPort 0

BridgeRelay 1
ORPort ${ORPORT}
Address ${PUBLIC_IP}

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:${BRIDGE_PORT}

ExtORPort auto
PublishServerDescriptor 0

DataDirectory ${DATA_DIR}
Log notice syslog
EOF

log "Preparing tor@default (Ubuntu 22.04 multi-instance)..."
mkdir -p /etc/tor/instances.d
touch /etc/tor/instances.d/default

# Stop master if present (not fatal)
systemctl stop tor >/dev/null 2>&1 || true
systemctl disable tor >/dev/null 2>&1 || true

log "Resetting Tor state (pt_state) and permissions..."
systemctl stop tor@default >/dev/null 2>&1 || true
rm -rf "${PT_STATE_DIR}" || true
mkdir -p "${DATA_DIR}"
chown -R "${TOR_USER}:${TOR_USER}" "${DATA_DIR}"

log "Starting tor@default (no enable; unit may be static)..."
systemctl daemon-reload
systemctl restart tor@default

log "Waiting for Tor to initialize (fingerprint)..."
elapsed=0
while [[ ! -s "${FINGERPRINT_FILE}" ]]; do
  sleep 2
  elapsed=$((elapsed + 2))
  if (( elapsed >= TIMEOUT_SEC )); then
    warn "Timeout waiting for ${FINGERPRINT_FILE}"
    warn "Status:"
    systemctl status tor@default --no-pager || true
    warn "Logs:"
    journalctl -u tor@default -n 200 --no-pager || true
    die "Tor did not create fingerprint in time."
  fi
done

FP="$(sudo -u "${TOR_USER}" awk 'NF==1{print $1; exit}' "${FINGERPRINT_FILE}" 2>/dev/null || true)"
[[ -n "${FP}" ]] || die "Could not read fingerprint from ${FINGERPRINT_FILE}"

# Extract cert/iat-mode from pt_state (txt or json)
CERT="$(sudo -u "${TOR_USER}" grep -Eo 'cert=[^ ]+' "${BRIDGELINE_TXT}" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"
IAT="$(sudo -u "${TOR_USER}" grep -Eo 'iat-mode=[0-9]+' "${BRIDGELINE_TXT}" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"

if [[ -z "${CERT}" ]]; then
  CERT="$(sudo -u "${TOR_USER}" sed -n 's/.*"cert"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${BRIDGESTATE_JSON}" 2>/dev/null | head -n 1 || true)"
fi
if [[ -z "${IAT}" ]]; then
  IAT="$(sudo -u "${TOR_USER}" sed -n 's/.*"iatMode"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${BRIDGESTATE_JSON}" 2>/dev/null | head -n 1 || true)"
fi
[[ -n "${IAT}" ]] || IAT="0"
[[ -n "${CERT}" ]] || die "Could not extract cert from pt_state. Check logs: sudo journalctl -u tor@default -n 200 --no-pager"

echo
echo "==================== YOUR TOR OBF S4 BRIDGE ===================="
echo "obfs4 ${PUBLIC_IP}:${BRIDGE_PORT} ${FP} cert=${CERT} iat-mode=${IAT}"
echo "================================================================"
echo
log "IMPORTANT: also open TCP/${BRIDGE_PORT} in your VPS provider firewall panel (if enabled)."
