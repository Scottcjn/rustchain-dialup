#!/usr/bin/env bash
# mask-modemmanager-for-acm.sh — RustChain Dial-Up (Bounty D1)
#
# Why this script exists:
#   The Pi's ModemManager (MM) service fights mgetty for /dev/ttyACM*.
#   When MM claims the port, mgetty cannot open it, the modem never
#   answers, and the whole bench test fails. The standard mitigation
#   is to mask MM *for the ACM devices* while leaving the rest of the
#   network stack alone.
#
# What this script does (idempotent):
#   1. Stops and masks the ModemManager service at the systemd level.
#   2. Installs a udev rule (config/modemmanager-override.conf) that
#      tells MM to skip any device with ID_PATH matching the Dell
#      NW147 / Conexant RD02-D400.
#   3. Installs a systemd drop-in for serial-getty@.service that
#      excludes ttyACM* and ttyModem* so no getty competes with mgetty
#      on the answer line.
#   4. Reloads systemd + udev, then restarts mgetty@ttyModem0 if it
#      was already running.
#
# Reversibility: run with --undo to undo every change.
#
# Safety: this script does NOT touch any other systemd service, does
# NOT modify hermes-gateway, does NOT modify the kernel. It only:
#   - masks modemmanager.service
#   - drops two files in /etc/
#   - daemon-reloads
# You can rerun --undo to remove the drop-ins and unmask the service.

set -euo pipefail

ACTION="${1:-apply}"

log() { echo "[d1-mask-mm] $*"; }

UDEV_RULE_DST="/etc/udev/rules.d/99-rustchain-dialup-mm-override.rules"
SERIAL_GETTY_DROPIN_DIR="/etc/systemd/system/serial-getty@.service.d"
SERIAL_GETTY_DROPIN="${SERIAL_GETTY_DROPIN_DIR}/99-rustchain-dialup-no-acm.conf"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

apply() {
  log "Step 1/4: mask ModemManager service"
  systemctl stop ModemManager.service 2>/dev/null || true
  systemctl mask ModemManager.service

  log "Step 2/4: install udev rule to keep MM off the answer modem"
  install -m 0644 "${SRC_DIR}/modemmanager-override.conf" "${UDEV_RULE_DST}"
  udevadm control --reload-rules

  log "Step 3/4: install serial-getty drop-in (skip ttyACM*, ttyModem*)"
  mkdir -p "${SERIAL_GETTY_DROPIN_DIR}"
  install -m 0644 "${SRC_DIR}/serial-getty-override.conf" "${SERIAL_GETTY_DROPIN}"
  systemctl daemon-reload

  log "Step 4/4: restart mgetty on the answer line if running"
  if systemctl is-active --quiet mgetty@ttyModem0.service 2>/dev/null; then
    systemctl try-restart mgetty@ttyModem0.service
  fi

  log "Done. Verify with:"
  log "  systemctl status ModemManager.service   # should be 'masked'"
  log "  cat ${UDEV_RULE_DST}"
  log "  cat ${SERIAL_GETTY_DROPIN}"
}

undo() {
  log "Removing rustchain-dialup overrides"
  rm -f "${UDEV_RULE_DST}" "${SERIAL_GETTY_DROPIN}"
  rmdir "${SERIAL_GETTY_DROPIN_DIR}" 2>/dev/null || true
  udevadm control --reload-rules
  systemctl unmask ModemManager.service
  systemctl daemon-reload
  log "Done. ModemManager unmasked; udev + systemd configs restored."
}

case "${ACTION}" in
  apply) apply ;;
  --undo|undo) undo ;;
  *)
    echo "Usage: $0 [apply|--undo]" >&2
    exit 64
    ;;
esac
