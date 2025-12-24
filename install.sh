#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Tor obfs4 PRIVATE bridge installer (Ubuntu 22.04)
#
# Goals:
# - Keep SSH access (UFW allows OpenSSH/22 before enabling)
# - Auto-pick a free non-privileged port (or use BRIDGE_PORT)
# - Configure Tor as a PRIVATE obfs4 bridge
# - Use tor@default (Ubuntu 22.04 multi-instance)
# - Handle apt/dpkg lock (waits for unattended upgrades)
# - Print ONE final block:
#   ==================== YOUR TOR OBF S4 BRIDGE ====================
#   obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0
#   =================================================================
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Ro-droid-wq/tor-obfs4-bridge/main/install.sh | sudo bash
#
# Optional env:
#   BRIDGE_PORT=9443
#   PORT_CANDIDATES="8443 9443 10443 12443 14443 16443 18443"
#   ORPORT=9001
#   TIMEOUT_SEC=300
#   APT_WAIT_SEC=300
# ==========================================================

ORPORT="${ORPORT:-9001}"
TIMEOUT_SEC="${TIMEOUT_SEC:-300}"
APT_WAIT_SEC="${APT_WAIT_SEC:-300}"
TOR_USER="debian-tor"

TORRC_PATH="/etc/tor/torrc"
DATA_DIR="/var/lib/tor"
PT_STATE_DIR="${DATA_DIR}/pt_state"
BRIDGELINE_TXT="${PT_STATE_DIR}/obfs4_bridgeline.txt"
BRIDGESTATE_JSON="${PT_STATE_DIR}/obfs4_state.json"
FINGERPRINT_FILE="${DATA_DIR}/fingerprint"

log(){ echo "[+] $*"; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[x] $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"

# ---------- helpers ----------
dpkg_locked() {
  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1
}

wait_for_apt_lock() {
  local elapsed=0
  while dpkg_locked; do
    if (( elapsed >= APT_WAIT_SEC )); then
      warn "dpkg lock is still held after ${APT_WAIT_SEC}s."
      warn "Processes holding the lock:"
      fuser -v /var/lib/dpkg/lock-frontend || true
      die "Cannot continue while apt/dpkg is busy."
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
}

pick_free_port() {
  local candidates=("$@")
  local p
  for p in "${candidates[@]}"; do
    if ! ss -lnt "( sport = :$p )" 2>/dev/null | tail -n +2 | grep -q .; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

get_public_ip() {
  # Best-effort public IP detection
  curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true
}

ensure_dir_perms() {
  mkdir -p "${DATA_DIR}"
  chown -R "${TOR_USER}:${TOR_USER}" "${DATA_DIR}"
  chmod 700 "${DATA_DIR}"
}

# Robust fingerprint read (supports "Unnamed <FP>" or "<FP>")
read_fingerprint() {
  local fp=""
  if [[ -s "${FINGERPRINT_FILE}" ]]; then
    fp="$(sudo -u "${TOR_USER}" awk 'NR==1{ if (NF>=2) {print $2} else {print $1} }' "${FINGERPRINT_FILE}" 2>/dev/null || true)"
    [[ -n "${fp}" ]] || fp="$(sudo -u "${TOR_USER}" awk 'NF==1{print $1; exit}' "${FINGERPRINT_FILE}" 2>/dev/null || true)"
  fi
  echo "${fp}"
}

# Extract cert/iat-mode from txt or json (best-effort)
extract_cert_iat() {
  local cert="" iat=""

  if [[ -s "${BRIDGELINE_TXT}" ]]; then
    cert="$(sudo -u "${TOR_USER}" grep -Eo 'cert=[^ ]+' "${BRIDGELINE_TXT}" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"
    iat="$(sudo -u "${TOR_USER}"  grep -Eo 'iat-mode=[0-9]+' "${BRIDGELINE_TXT}" 2>/dev/null | head -n 1 | cut -d= -f2 || true)"
  fi

  if [[ -z "${cert}" && -s "${BRIDGESTATE_JSON}" ]]; then
    cert="$(sudo -u "${TOR_USER}" sed -n 's/.*"cert"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${BRIDGESTATE_JSON}" 2>/dev/null | head -n 1 || true)"
  fi

  if [[ -z "${iat}" && -s "${BRIDGESTATE_JSON}" ]]; then
    iat="$(sudo -u "${TOR_USER}" sed -n 's/.*"iatMode"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${BRIDGESTATE_JSON}" 2>/dev/null | head -n 1 || true)"
    [[ -n "${iat}" ]] || iat="$(sudo -u "${TOR_USER}" sed -n 's/.*"iat-mode"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${BRIDGESTATE_JSON}" 2>/dev/null | head -n 1 || true)"
  fi

  [[ -n "${iat}" ]] || iat="0"
  echo "${cert}|${iat}"
}

# ---------- choose port ----------
PORT_CANDIDATES_STR="${PORT_CANDIDATES:-8443 9443 10443 12443 14443 16443 18443}"
read -r -a PORT_CANDIDATES <<< "${PORT_CANDIDATES_STR}"

if [[ -n "${BRIDGE_PORT:-}" ]]; then
  log "Using user-specified BRIDGE_PORT=${BRIDGE_PORT}"
else
  BRIDGE_PORT="$(pick_free_port "${PORT_CANDIDATES[@]}")" || die "No free port found in: ${PORT_CANDIDATES_STR}"
  log "Auto-selected free bridge port: ${BRIDGE_PORT}"
fi

# ---------- apt install ----------
wait_for_apt_lock
log "Installing packages (tor, obfs4proxy, ufw, curl)..."
apt-get update -y
apt-get install -y tor obfs4proxy ufw curl

# ---------- firewall ----------
log "Configuring UFW (keep SSH)..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 22/tcp >/dev/null 2>&1 || true
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable >/dev/null
fi
ufw allow "${BRIDGE_PORT}/tcp" >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

# ---------- torrc ----------
PUBLIC_IP="$(get_public_ip)"
[[ -n "${PUBLIC_IP}" ]] || die "Could not detect public IP (api.ipify.org blocked). Set Address manually in /etc/tor/torrc."

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

# ---------- multi-instance (tor@default) ----------
log "Preparing tor@default (Ubuntu 22.04 multi-instance)..."
mkdir -p /etc/tor/instances.d
touch /etc/tor/instances.d/default

# Disable master unit if present (not fatal if already absent)
systemctl stop tor >/dev/null 2>&1 || true
systemctl disable tor >/dev/null 2>&1 || true

# Reset pt_state so we always get fresh cert/state for the chosen port
log "Resetting Tor state (pt_state) and permissions..."
systemctl stop tor@default >/dev/null 2>&1 || true
rm -rf "${PT_STATE_DIR}" >/dev/null 2>&1 || true
ensure_dir_perms

log "Starting tor@default (unit may be static; no enable)..."
systemctl daemon-reload
systemctl restart tor@default

# ---------- wait for fingerprint + cert ----------
log "Waiting for Tor to initialize (fingerprint + pt_state)..."
elapsed=0
FP=""
CERT=""
IAT="0"

while (( elapsed < TIMEOUT_SEC )); do
  FP="$(read_fingerprint)"
  if [[ -n "${FP}" ]]; then
    pair="$(extract_cert_iat)"
    CERT="${pair%%|*}"
    IAT="${pair##*|}"
    if [[ -n "${CERT}" ]]; then
      break
    fi
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done

if [[ -z "${FP}" ]]; then
  warn "Could not read fingerprint from ${FINGERPRINT_FILE}"
  warn "Status:"
  systemctl status tor@default --no-pager || true
  warn "Logs:"
  journalctl -u tor@default -n 200 --no-pager || true
  die "Fingerprint not available."
fi

if [[ -z "${CERT}" ]]; then
  warn "Could not extract cert from pt_state (txt/json)."
  warn "Status:"
  systemctl status tor@default --no-pager || true
  warn "Logs:"
  journalctl -u tor@default -n 200 --no-pager || true
  warn "pt_state listing:"
  ls -la "${PT_STATE_DIR}" || true
  die "cert not available."
fi

# ---------- final single message ----------
echo
echo "==================== YOUR TOR OBF S4 BRIDGE ===================="
echo "obfs4 ${PUBLIC_IP}:${BRIDGE_PORT} ${FP} cert=${CERT} iat-mode=${IAT}"
echo "================================================================"
echo
log "IMPORTANT: also open TCP/${BRIDGE_PORT} in your VPS provider firewall panel (if enabled)."
