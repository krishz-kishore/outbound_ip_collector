#!/bin/bash

set -euo pipefail

# 1) Prompt user for the interface
read -rp "Enter the network interface (e.g., eth0, ens5): " IFACE

# 2) Define and create the base directory
BASE_DIR="/var/log/outbound_collector"
if [[ ! -d "$BASE_DIR" ]]; then
  sudo mkdir -p "$BASE_DIR"
  sudo chown root:root "$BASE_DIR"
  sudo chmod 750 "$BASE_DIR"
fi

# Paths inside the collection directory
PCAP_PATTERN="$BASE_DIR/conn-all-%Y%m%d%H%M.pcap"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.txt"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"

# Path for the extraction script
EXTRACT_SCRIPT="/usr/local/bin/extract_unique_ips.sh"

# 3) Start tcpdump in the background, rotating hourly (keep last 24)
echo "[+] Starting tcpdump (rotating, 24 files) on interface $IFACE..."
sudo nohup tcpdump -n -i "$IFACE" -s 0 \
  -G 3600 -W 24 \
  -w "$PCAP_PATTERN" \
  > /dev/null 2>>"$LOG_FILE" &

if [[ $? -ne 0 ]]; then
  echo "[!] Failed to start tcpdump. Check $LOG_FILE for details." >&2
  exit 1
fi

# 4) Create the extraction script (reads from $BASE_DIR)
sudo tee "$EXTRACT_SCRIPT" > /dev/null << 'EOF'
#!/bin/bash
#
# /usr/local/bin/extract_unique_ips.sh
#
#   - Scans all “conn-all-*.pcap” files in /var/log/outbound_collector
#     that were modified in the last 12 hours (mmin -720).
#   - Extracts unique destination IPs.
#   - Merges them into one cumulative file: unique_ips.txt in that same directory.
#   - Logs activity into outbound_ip_collector.log.
#   - Re-schedules itself via at for another run in 12 hours.
#

set -euo pipefail

BASE_DIR="/var/log/outbound_collector"
UNIQUE_IP_FILE="$BASE_DIR/unique_ips.txt"
TEMP_IPS="/tmp/recent_ips_$$.txt"
LOG_FILE="$BASE_DIR/outbound_ip_collector.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "[*] Starting IP extraction."

# Check for required commands
for cmd in find tcpdump awk at sort mv wc; do
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

  # Extract destination IPs from all PCAPs
  > "$TEMP_IPS"
  while read -r PCAP; do
    log "[*] Processing $PCAP"
    if ! sudo tcpdump -nnr "$PCAP" 2>/dev/null | \
      awk '{
        for(i=1;i<=NF;i++){
          if ($i ~ />/) {
            split($(i+1), b, ".")
            ip = b[1]"."b[2]"."b[3]"."b[4]
            if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print ip
          }
        }
      }' >> "$TEMP_IPS"; then
      log "[ERROR] Failed to extract IPs from $PCAP"
    else
      log "[✓] Extracted IPs from $PCAP"
    fi
  done <<< "$PCAP_FILES"

  COUNT=$(wc -l < "$TEMP_IPS")
  log "[*] Total extracted IPs: $COUNT"

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

FINAL_COUNT=$(wc -l < "$UNIQUE_IP_FILE" 2>/dev/null || echo 0)
log "[✓] Unique IP list updated ($FINAL_COUNT entries)."

# Schedule this script to run in 12 hours
if echo "$0" | at now + 12 hours 2>>"$LOG_FILE"; then
  log "[*] Next extraction scheduled via at (now + 12 hours)."
else
  log "[ERROR] Failed to schedule next run with 'at'."
fi

log "[*] Script completed."
EOF

# 5) Make the extraction script executable
sudo chmod 750 "$EXTRACT_SCRIPT"

# 6) Schedule it once (after 12 hours) to start the recurring chain
echo "[+] Scheduling first IP extraction in 12 hours..."
echo "$EXTRACT_SCRIPT" | at now + 12 hours 2>>"$LOG_FILE"

echo "[✓] Setup complete."
echo "    • All PCAPs → $BASE_DIR/conn-all-*.pcap"
echo "    • Unique IP file → $UNIQUE_IP_FILE"
echo "    • Log file → $LOG_FILE"
echo "    • Extraction script → $EXTRACT_SCRIPT (runs every 12 hrs via at)"
