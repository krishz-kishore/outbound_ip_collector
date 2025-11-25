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
log "[*] Removing scheduled cron job for extract script."
if sudo crontab -l 2>/dev/null | grep -F "$EXTRACT_SCRIPT" >/dev/null 2>&1; then
  sudo crontab -l 2>/dev/null | grep -v -F "$EXTRACT_SCRIPT" | sudo crontab -
  log "[✓] Removed cron job for $EXTRACT_SCRIPT."
else
  log "[!] No cron job found for $EXTRACT_SCRIPT."
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
