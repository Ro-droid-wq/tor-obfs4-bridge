#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Tor obfs4 PRIVATE bridge installer (Ubuntu 22.04)
# Output: one final "message" block with a ready obfs4 bridge line
#
# What it does:
# - Installs tor + obfs4proxy + ufw + curl
# - Keeps SSH access (allows OpenSSH/22 before enabling UFW)
# - Opens BRIDGE_PORT (default 8443) in UFW
# - Writes /etc/tor/torrc for a private obfs4 bridge
# - Uses tor@default (Ubuntu 22.04 multi-instance)
# - Extracts REAL components (IP + FINGERPRINT + cert + iat-mode)
# - Prints exactly one final block for copy/paste into Tor Browser
#
# Usage:
#   sudo bash install.sh
# Optional env:
#   BRIDGE_PORT=9443 ORPORT=9001 TIMEOUT_SEC=240
# ==========================================================

BRIDGE_PORT="${BRIDGE_PORT:-8443}"
ORPORT="${ORPORT:-9001}"
TIMEOUT_SEC="${TIMEOUT_SEC:-240}"

TORRC_PATH="/etc/tor/torrc"
TOR_USER="debian-tor"
BRIDGELINE_TXT="/var/lib/tor/pt_state/obfs4_bridgeline.txt"
BRIDGESTATE_JSON="/var/lib/tor/pt_state/obfs4_state.json"
FINGERPRINT_FILE="/var/lib/tor/fingerprint"

log() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die() { echo "[x] $*" >&2; exit 1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"
}

install_pkgs() {
  log "Installing packages..."
  apt-get update -y
  apt-get install -y tor obfs4proxy ufw curl
}

setup_ufw() {
  log "Configuring UFW (keep SSH)..."
  ufw allow OpenSSH >/dev/null 2>&1 || true
  ufw allow 22/tcp >/dev/null 2>&1 || true
  if ! ufw status | grep -q "Status: active"; then
    ufw --force enable >/dev/null
  fi
  ufw allow "${BRIDGE_PORT}/tcp" >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
}

get_public_ip() {
  # Best-effort; if blocked, return empty.
  curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true
}

write_torrc() {
  local ip="$1"
  log "Writing torrc..."
  cat > "${TORRC_PATH}" <<EOF
############ PRIVATE TOR BRIDGE (obfs4) ############

RunAsDaemon 1
SocksPort 0

BridgeRelay 1
ORPort ${ORPORT}
Address ${ip}

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:${BRIDGE_PORT}

ExtORPort auto
PublishServerDescriptor 0

DataDirectory /var/lib/tor
Log notice syslog
EOF
}

ensure_instance_mode() {
  log "Preparing tor@default (Ubuntu 22.04 multi-instance)..."
  mkdir -p /etc/tor/instances.d
  touch /etc/tor/instances.d/default

  # Disable master to avoid confusion
  systemctl stop tor >/dev/null 2>&1 || true
  systemctl disable tor >/dev/null 2>&1 || true
}

restart_tor_instance_clean() {
  log "Restarting tor@default (clean pt_state)..."
  systemctl stop tor@default >/dev/null 2>&1 || true

  # Remove pt_state so obfs4 regenerates cleanly
  rm -rf /var/lib/tor/pt_state || true
  mkdir -p /var/lib/tor
  chown -R "${TOR_USER}:${TOR_USER}" /var/lib/tor

  systemctl daemon-reload
  systemctl enable --now tor@default
}

wait_for_files() {
  log "Waiting for Tor to initialize..."
  local elapsed=0
  while (( elapsed < TIMEOUT_SEC )); do
    # fingerprint exists when tor initialized
    if [[ -s "${FINGERPRINT_FILE}" ]]; then
      # bridgeline or state json may appear later
      if [[ -s "${BRIDGELINE_TXT}" || -s "${BRIDGESTATE_JSON}" ]]; then
        return 0
      fi
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

get_fingerprint() {
  # /var/lib/tor/fingerprint: "Unnamed ...\n<FP>\n"
  sudo -u "${TOR_USER}" awk 'NF==1{print $1; exit}' "${FINGERPRINT_FILE}" 2>/dev/null || true
}

get_cert_and_iat_from_txt() {
  local cert="" iat=""
  if [[ -s "${BRIDGELINE_TXT}" ]]; then
    cert="$(sudo -u "${TOR_USER}" grep -Eo 'cert=[^ ]+' "${BRIDGELINE_TXT}" | head -n 1 | cut -d= -f2 || true)"
    iat="$(sudo -u "${TOR_USER}" grep -Eo 'iat-mode=[0-9]+' "${BRIDGELINE_TXT}" | head -n 1 | cut -d= -f2 || true)"
  fi
  echo "${cert}|${iat}"
}

get_cert_and_iat_from_json() {
  # Minimal JSON parsing without jq: extract "cert":"..." and "iatMode":0 (common)
  local cert="" iat=""
  if [[ -s "${BRIDGESTATE_JSON}" ]]; then
    cert="$(sudo -u "${TOR_USER}" sed -n 's/.*"cert"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${BRIDGESTATE_JSON}" | head -n 1 || true)"
    # iat-mode might be stored as "iatMode":0 or "iat-mode":0 depending on versions
    iat="$(sudo -u "${TOR_USER}" sed -n 's/.*"iatMode"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${BRIDGESTATE_JSON}" | head -n 1 || true)"
    if [[ -z "${iat}" ]]; then
      iat="$(sudo -u "${TOR_USER}" sed -n 's/.*"iat-mode"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${BRIDGESTATE_JSON}" | head -n 1 || true)"
    fi
  fi
  echo "${cert}|${iat}"
}

main() {
  need_root
  install_pkgs
  setup_ufw

  local ip
  ip="$(get_public_ip)"
  [[ -n "${ip}" ]] || die "Could not detect public IP (api.ipify.org blocked). Set it manually by editing /etc/tor/torrc (Address X.X.X.X)."

  write_torrc "${ip}"
  ensure_instance_mode
  restart_tor_instance_clean

  if ! wait_for_files; then
    warn "Timeout waiting for Tor files."
    warn "Check logs: sudo journalctl -u tor@default -n 200 --no-pager"
    die "Tor did not initialize in time."
  fi

  local fp cert iat pair
  fp="$(get_fingerprint)"
  [[ -n "${fp}" ]] || die "Could not read fingerprint from ${FINGERPRINT_FILE}"

  # Try to get cert/iat from bridgeline.txt first; if empty, from state json.
  pair="$(get_cert_and_iat_from_txt)"
  cert="${pair%%|*}"
  iat="${pair##*|}"

  if [[ -z "${cert}" || -z "${iat}" ]]; then
    pair="$(get_cert_and_iat_from_json)"
    cert="${pair%%|*}"
    iat="${pair##*|}"
  fi

  [[ -n "${cert}" ]] || die "Could not extract cert (pt_state not ready). Check: sudo journalctl -u tor@default -n 200 --no-pager"
  [[ -n "${iat}" ]] || iat="0"

  # Final output: exactly one block
  echo
  echo "==================== YOUR TOR OBF S4 BRIDGE ===================="
  echo "obfs4 ${ip}:${BRIDGE_PORT} ${fp} cert=${cert} iat-mode=${iat}"
  echo "================================================================"
  echo
}

main "$@"
