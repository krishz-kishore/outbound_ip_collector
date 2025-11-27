#!/bin/bash

set -euo pipefail

# 1) Prompt user for the interface
read -rp "Enter the network interface (e.g., eth0, ens5): " IFACE

# 2) Define and create the base directory
BASE_DIR="${BASE_DIR:-/var/log/outbound_collector}"
if [[ ! -d "$BASE_DIR" ]]; then
  # Create the fallback directory
  sudo mkdir -p /tmp/outbound_collector
  sudo chown root:root /tmp/outbound_collector
  sudo mkdir -p "$BASE_DIR"
  sudo chown root:root "$BASE_DIR"
  sudo chmod 750 "$BASE_DIR"
fi

# Preflight: ensure tcpdump can be executed with sufficient privileges
preflight_tcpdump() {
  if ! command -v tcpdump >/dev/null 2>&1; then
    echo "[ERROR] tcpdump binary not found; please install it (apt/yum install tcpdump)"
    exit 1
  fi
  # Try listing interfaces via sudo tcpdump -D as permission test
  if ! sudo tcpdump -D >/dev/null 2>&1; then
    echo "[WARN] Unable to run 'sudo tcpdump -D' — you may not have permission to run tcpdump or sudo may require a password."
    echo "  - Try: sudo tcpdump -D"
    echo "  - Or add capabilities to tcpdump so it can be executed without root: sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)"
    echo "  - Or ensure you're running the script as root (use: sudo ./outbound_ip_collector.sh)"
  fi
}

preflight_tcpdump

# Paths inside the collection directory
PCAP_PATTERN="$BASE_DIR/conn-all-%Y%m%d%H%M.pcap"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.txt"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"

# Path for the extraction script
EXTRACT_SCRIPT="/usr/local/bin/extract_unique_ips.sh"

# 3) Start tcpdump in the background, rotating hourly (keep last 24)
echo "[+] Starting tcpdump (rotating, 24 files) on interface $IFACE..."
# Kill any existing tcpdump started by this script. Avoid leaving duplicates.
if pgrep -f "tcpdump .*conn-all-" >/dev/null 2>&1; then
  echo "[i] Existing tcpdump capture detected — stopping it first"
  sudo pkill -f "tcpdump .*conn-all-" || true
fi
# Start tcpdump as root and set umask to ensure readable pcaps for analysis (0644)
sudo bash -lc "umask 0022; nohup tcpdump -n -i \"$IFACE\" -s 0 -G 3600 -W 24 -w \"$PCAP_PATTERN\" > /dev/null 2>>\"$LOG_FILE\" &"

if [[ $? -ne 0 ]]; then
  echo "[!] Failed to start tcpdump. Check $LOG_FILE for details." >&2
  exit 1
fi

# 4) Create the extraction script (reads from $BASE_DIR)
sudo tee "$EXTRACT_SCRIPT" > /dev/null << 'EOF'
  # Prompt for base directory with default
  read -rp "Enter the base directory for captures and logs [/var/log/outbound_collector]: " USER_BASE_DIR
  if [[ -z "$USER_BASE_DIR" ]]; then
    BASE_DIR="${BASE_DIR:-/var/log/outbound_collector}"
  else
    BASE_DIR="$USER_BASE_DIR"
  fi
#!/bin/bash
  if [[ ! -d "$BASE_DIR" ]]; then
    echo "[i] Creating base directory: $BASE_DIR"
    if sudo mkdir -p "$BASE_DIR" 2>/dev/null; then
      sudo chown root:root "$BASE_DIR"
      sudo chmod 750 "$BASE_DIR"
    else
      echo "[WARN] Failed to create $BASE_DIR (permission denied)."
      # Try fallback
      FALLBACK_DIR="/tmp/outbound_collector"
      echo "[i] Using fallback base directory: $FALLBACK_DIR"
      BASE_DIR="$FALLBACK_DIR"
      sudo mkdir -p "$BASE_DIR"
      sudo chown root:root "$BASE_DIR"
      sudo chmod 750 "$BASE_DIR"
    fi
  fi
#   - Merges them into one cumulative file: unique_ips.txt in that same directory.
#   - Logs activity into outbound_ip_collector.log.
#   - Run via cron every 12 hours (cron installed/managed by setup script).
#

set -euo pipefail

  EXTRACT_SCRIPT="/usr/local/bin/extract_unique_ips.sh"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.txt"
TEMP_IPS="/tmp/recent_ips_$$.txt"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "[*] Starting IP extraction."

# Check for required commands
for cmd in find tcpdump awk sort mv wc; do
  if ! command -v $cmd &>/dev/null; then
    log "[ERROR] Required command '$cmd' not found. Exiting."
    exit 1
  fi
done

# Find all PCAPs in BASE_DIR modified in last 12 hours (720 minutes)
PCAP_FILES=$(find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' -mmin -720 2>/dev/null)
if [[ -z "$PCAP_FILES" ]]; then
  log "[WARN] No recent PCAP files found. Nothing to process."
else
  log "[*] Found PCAP files:"
  echo "$PCAP_FILES" | while read -r f; do log "    $f"; done

  # Extract destination IPs, ports, protocol, and packet size from all PCAPs
  > "$TEMP_IPS"
  while read -r PCAP; do
    log "[*] Processing $PCAP"
    if ! sudo tcpdump -nnr "$PCAP" 2>/dev/null | \
      awk '{
        for(i=1;i<=NF;i++){
          if ($i ~ />/) {
            split($(i+1), b, ".")
            ip = b[1]"."b[2]"."b[3]"."b[4]
            port = b[5]
            protocol = $1
            size = $(NF-1)
            if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
              print ip, port, protocol, size
            }
          }
        }
      }' >> "$TEMP_IPS"; then
      log "[ERROR] Failed to extract data from $PCAP"
    else
      log "[✓] Extracted data from $PCAP"
    fi
  done <<< "$PCAP_FILES"

  COUNT=$(wc -l < "$TEMP_IPS")
  log "[*] Total extracted entries: $COUNT"

  # Merge with existing UNIQUE_IP_FILE (if present), dedupe, write back
  if [[ -f "$UNIQUE_IP_FILE" ]]; then
    log "[*] Merging with existing unique IP file."
    if cat "$TEMP_IPS" "$UNIQUE_IP_FILE" | sort -u > "$BASE_DIR/combined_ips_$$.txt"; then
      if sudo mv "$BASE_DIR/combined_ips_$$.txt" "$UNIQUE_IP_FILE"; then
        log "[✓] Updated $UNIQUE_IP_FILE with merged IPs."
      else
        log "[ERROR] Failed to move combined IPs to $UNIQUE_IP_FILE."
        exit 1
      fi
    else
      log "[ERROR] Failed to create combined IPs file."
      exit 1
    fi
  else
    log "[*] No existing unique IP file, creating new one."
    if sudo mv "$TEMP_IPS" "$UNIQUE_IP_FILE"; then
      log "[✓] Created new $UNIQUE_IP_FILE."
    else
      log "[ERROR] Failed to create $UNIQUE_IP_FILE."
      exit 1
    fi
  fi

  # Clean up temp file
  rm -f "$TEMP_IPS"
fi

  # Make captured PCAP files readable by analysis tools (if created by root)
  if [[ -d "$BASE_DIR" ]]; then
    sudo find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' -exec chmod 0644 {} \; 2>/dev/null || true
  fi

FINAL_COUNT=$(wc -l < "$UNIQUE_IP_FILE" 2>/dev/null || echo 0)
log "[✓] Unique IP list updated ($FINAL_COUNT entries)."

# (No scheduling here — the job is expected to be scheduled by cron.)
log "[*] Extract script run completed (cron scheduling should be used)."

log "[*] Script completed."
EOF

# 5) Make the extraction script executable
sudo chmod 750 "$EXTRACT_SCRIPT"

# 6) Install cron job to run the extractor every 12 hours (as root)
if command -v systemctl >/dev/null 2>&1; then
  echo "[+] systemd detected — installing systemd service + timer for tcpdump"
  # Create an environment file for the service containing IFACE
    # Ask which user to run tcpdump as
    read -rp "Enter user to run tcpdump as [root]: " TCPDUMP_USER
    if [[ -z "$TCPDUMP_USER" ]]; then
      TCPDUMP_USER=root
    fi
    sudo tee /etc/default/outbound_ip_collector > /dev/null <<EOE
# Outbound IP Collector defaults
IFACE=$IFACE
LOG_FILE=$LOG_FILE
    TCPDUMP_USER=$TCPDUMP_USER
EOE
  # Optionally give tcpdump binary the capability to capture without root
  if [[ "$TCPDUMP_USER" != "root" ]]; then
    read -rp "Grant CAP_NET_RAW, CAP_NET_ADMIN to tcpdump binary so it can run as non-root? [y/N]: " GRANT_CAP
    if [[ "$GRANT_CAP" =~ ^([yY][eE][sS]|[yY])$ ]]; then
      sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump) || echo "[WARN] setcap failed; you may need libcap installed and run as root"
      echo "[i] tcpdump capabilities set; non-root user should be able to capture now"
    fi
  fi
  # Copy systemd unit files into place and reload daemon
  sudo cp "$(pwd)/systemd/outbound-tcpdump.service" /etc/systemd/system/outbound-tcpdump.service
  sudo cp "$(pwd)/systemd/outbound-tcpdump.timer" /etc/systemd/system/outbound-tcpdump.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now outbound-tcpdump.service
  sudo systemctl enable --now outbound-tcpdump.timer
  echo "[✓] outbound-tcpdump.service and timer installed and started via systemd"
  # Remove a cron job if one existed to avoid duplication
  if sudo crontab -l 2>/dev/null | grep -F "$EXTRACT_SCRIPT" >/dev/null 2>&1; then
    sudo crontab -l 2>/dev/null | grep -v -F "$EXTRACT_SCRIPT" | sudo crontab -
    echo "[i] Removed cron job to avoid duplication (systemd used)."
  fi
  # Check service status and fallback if there's a permission-related failure
  if ! sudo systemctl is-active --quiet outbound-tcpdump.service; then
    echo "[WARN] systemd service failed to start; checking journal for hints..."
    sudo journalctl -u outbound-tcpdump.service -n 50 --no-pager | sed -n '1,200p' | sed 's/^/[journal] /'
    # If the journal shows permission denied, switch to fallback base dir and restart the service
    if sudo journalctl -u outbound-tcpdump.service -n 50 --no-pager | grep -i "permission denied" >/dev/null 2>&1; then
      echo "[WARN] Permission denied detected in service logs; switching to fallback base directory /tmp/outbound_collector and restarting service"
      sudo mkdir -p /tmp/outbound_collector
      sudo chown "$TCPDUMP_USER":"$TCPDUMP_USER" /tmp/outbound_collector
      sudo chmod 0750 /tmp/outbound_collector
      sudo sed -i -e 's@BASE_DIR=.*@BASE_DIR=/tmp/outbound_collector@' /etc/default/outbound_ip_collector || true
      sudo systemctl daemon-reload
      sudo systemctl restart outbound-tcpdump.service
      if sudo systemctl is-active --quiet outbound-tcpdump.service; then
        echo "[✓] Service restarted successfully using /tmp/outbound_collector"
      else
        echo "[ERROR] Service still failing to start after fallback. Please inspect journalctl and SELinux/AppArmor settings."
      fi
    fi
  fi
else
  echo "[+] Installing cron job (every 12 hours) for $EXTRACT_SCRIPT..."
  CRON_JOB="0 */12 * * * $EXTRACT_SCRIPT >> $LOG_FILE 2>&1"
  if sudo crontab -l 2>/dev/null | grep -F "$EXTRACT_SCRIPT" >/dev/null 2>&1; then
    echo "[i] Cron job already exists for $EXTRACT_SCRIPT"
  else
    (sudo crontab -l 2>/dev/null || true; echo "$CRON_JOB") | sudo crontab -
    echo "[✓] Cron job installed: $CRON_JOB"
  fi
fi

echo "[✓] Setup complete."
echo "    • All PCAPs → $BASE_DIR/conn-all-*.pcap"
echo "    • Unique IP file → $UNIQUE_IP_FILE"
echo "    • Log file → $LOG_FILE"
echo "    • Extraction script → $EXTRACT_SCRIPT (runs every 12 hrs via cron)"
