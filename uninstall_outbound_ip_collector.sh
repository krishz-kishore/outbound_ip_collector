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

# Also try to stop systemd service if running
if command -v systemctl >/dev/null 2>&1; then
  if sudo systemctl is-active --quiet outbound-tcpdump.service; then
    sudo systemctl stop outbound-tcpdump.timer outbound-tcpdump.service || true
    log "[✓] Stopped outbound-tcpdump.service and timer (if present)."
  fi
fi

# Remove scheduled tasks
log "[*] Removing scheduled cron job for extract script (if present)."
if sudo crontab -l 2>/dev/null | grep -F "$EXTRACT_SCRIPT" >/dev/null 2>&1; then
  sudo crontab -l 2>/dev/null | grep -v -F "$EXTRACT_SCRIPT" | sudo crontab -
  log "[✓] Removed cron job for $EXTRACT_SCRIPT."
else
  log "[!] No cron job found for $EXTRACT_SCRIPT."
fi

# Remove systemd service and timer (if present)
log "[*] Removing systemd service/timer (if present)."
if command -v systemctl >/dev/null 2>&1; then
  if sudo systemctl is-active --quiet outbound-tcpdump.service; then
    sudo systemctl stop outbound-tcpdump.service || true
    log "[✓] Stopped outbound-tcpdump.service"
  fi
  if sudo systemctl is-enabled --quiet outbound-tcpdump.service; then
    sudo systemctl disable outbound-tcpdump.service || true
    log "[✓] Disabled outbound-tcpdump.service"
  fi
  if sudo systemctl is-active --quiet outbound-tcpdump.timer; then
    sudo systemctl stop outbound-tcpdump.timer || true
    log "[✓] Stopped outbound-tcpdump.timer"
  fi
  if sudo systemctl is-enabled --quiet outbound-tcpdump.timer; then
    sudo systemctl disable outbound-tcpdump.timer || true
    log "[✓] Disabled outbound-tcpdump.timer"
  fi
  # Remove unit files and environment file
  if [[ -f /etc/systemd/system/outbound-tcpdump.service || -f /etc/systemd/system/outbound-tcpdump.timer ]]; then
    sudo rm -f /etc/systemd/system/outbound-tcpdump.service /etc/systemd/system/outbound-tcpdump.timer
    sudo systemctl daemon-reload || true
    log "[✓] Removed systemd unit files and reloaded daemon"
  fi
  if [[ -f /etc/default/outbound_ip_collector ]]; then
    sudo rm -f /etc/default/outbound_ip_collector
    log "[✓] Removed /etc/default/outbound_ip_collector"
  fi
else
  log "[i] systemctl not present; skipping systemd cleanup"
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
