#!/bin/bash
# ENiGMA½ Locked Launcher
# This script authenticates dial-up users and starts ENiGMA½ BBS.

CONFIG_DIR="/etc/enigma-bbs"
BBS_BINARY="/usr/local/bin/enigma-bbs"
USER_DB="${CONFIG_DIR}/users.db"
LOG_FILE="/var/log/enigma_launcher.log"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Get username from environment (set by PPP)
USERNAME="${PEER_USERNAME:-${USER}}"

# Check if user is authorized
if [ -f "$USER_DB" ]; then
    if grep -q "^${USERNAME}:" "$USER_DB"; then
        log "User ${USERNAME} authenticated successfully."
    else
        log "Authentication failed for user ${USERNAME}."
        echo "Access denied."
        exit 1
    fi
else
    log "User database not found at ${USER_DB}. Starting BBS without authentication (fallback)."
fi

# Set environment variables
ENIGMA_BBS_CONFIG="${CONFIG_DIR}/config.yaml"
export ENIGMA_BBS_CONFIG

# Start BBS
if [ -x "$BBS_BINARY" ]; then
    log "Starting ENiGMA½ BBS for user ${USERNAME}..."
    exec "$BBS_BINARY" --config "$CONFIG_DIR"
else
    log "BBS binary not found at ${BBS_BINARY}."
    echo "Internal server error."
    exit 1
fi