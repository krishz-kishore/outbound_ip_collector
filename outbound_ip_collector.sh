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

{
  echo "[*] Starting IP extraction at: $(date)"

  # Find all PCAPs in BASE_DIR modified in last 12 hours (720 minutes)
  find "$BASE_DIR" -maxdepth 1 -type f -name 'conn-all-*.pcap' -mmin -720 2>/dev/null | \
  while read -r PCAP; do
    sudo tcpdump -nnr "$PCAP" 2>/dev/null
  done | awk '{
    for(i=1;i<=NF;i++){
      if ($i ~ />/) {
        split($(i+1), b, ".")
        ip = b[1]"."b[2]"."b[3]"."b[4]
        if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print ip
      }
    }
  }' > "$TEMP_IPS"

  # Merge with existing UNIQUE_IP_FILE (if present), dedupe, write back
  if [[ -f "$UNIQUE_IP_FILE" ]]; then
    cat "$TEMP_IPS" "$UNIQUE_IP_FILE" | sort -u > "$BASE_DIR/combined_ips_$$.txt"
    sudo mv "$BASE_DIR/combined_ips_$$.txt" "$UNIQUE_IP_FILE"
  else
    sudo mv "$TEMP_IPS" "$UNIQUE_IP_FILE"
  fi

  rm -f "$TEMP_IPS"

  echo "[✓] Unique IP list updated ($(wc -l < "$UNIQUE_IP_FILE") entries)."

  # Schedule this script to run in 12 hours
  echo "$0" | at now + 12 hours 2>>"$LOG_FILE"

  echo "[*] Next extraction scheduled via at (now + 12 hours)."

} >> "$LOG_FILE" 2>&1
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
