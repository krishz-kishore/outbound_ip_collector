#!/bin/bash

set -euo pipefail

# Define paths
BASE_DIR="/var/log/outbound_collector"
EXTRACT_SCRIPT="/usr/local/bin/extract_unique_ips.sh"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "[*] Starting uninstallation of Outbound IP Collector."

# Stop tcpdump processes
log "[*] Stopping any running tcpdump processes."
if pgrep tcpdump > /dev/null; then
  sudo pkill tcpdump
  log "[✓] Stopped tcpdump."
else
  log "[!] No tcpdump processes found."
fi

# Remove scheduled tasks
log "[*] Removing scheduled tasks for extract script."
if atq | grep -q "$EXTRACT_SCRIPT"; then
  atq | grep "$EXTRACT_SCRIPT" | awk '{print $1}' | xargs -r at -r
  log "[✓] Removed scheduled tasks."
else
  log "[!] No scheduled tasks found."
fi

# Remove files and directories
log "[*] Removing files and directories."
if [[ -d "$BASE_DIR" ]]; then
  sudo rm -rf "$BASE_DIR"
  log "[✓] Removed $BASE_DIR."
else
  log "[!] $BASE_DIR does not exist."
fi

if [[ -f "$EXTRACT_SCRIPT" ]]; then
  sudo rm -f "$EXTRACT_SCRIPT"
  log "[✓] Removed $EXTRACT_SCRIPT."
else
  log "[!] $EXTRACT_SCRIPT does not exist."
fi

# Final message
log "[✓] Uninstallation complete. Outbound IP Collector has been removed."
