# Outbound IP Collector

A simple solution to capture all outbound traffic from a Linux host, store hourly packet captures, and periodically extract unique destination IPs into a single file. All logs, PCAPs, and outputs are centralized in one directory for easy management.

---

## Table of Contents

- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Directory Structure](#directory-structure)  
- [Installation & Setup](#installation--setup)  
- [Usage](#usage)  
- [How It Works](#how-it-works)  
- [Scripts & Components](#scripts--components)  
- [Troubleshooting](#troubleshooting)  
- [License](#license)  

---

## Features

- **Continuous Packet Capture**  
  • Runs `tcpdump` on a user-specified interface, rotating hourly and keeping the last 24 PCAP files.  
- **Centralized Storage**  
  • All PCAPs, logs, and unique-IP output are stored under `/var/log/outbound_collector/`.  
- **Automated Unique IP Extraction**  
  • Every 12 hours, parses recent PCAPs to extract destination IPs, merges them into one deduplicated file.  
- **Self-Scheduling via `at`**  
  • The extraction task re-enqueues itself every 12 hours using the `at` command—no crontab needed.  
- **Minimal Dependencies**  
  • Only requires: `tcpdump`, `at`, and a standard Linux shell environment.
- **Enhanced Data Extraction**  
  • Extracts destination IPs, ports, protocol information, and packet size from PCAP files.  
  • Provides detailed insights into outbound traffic.

---

## Prerequisites

1. **Linux Host** (CentOS, Ubuntu, Debian, etc.)  
2. **Root (or `sudo`) access**  
3. **Installed Packages**  
   - `tcpdump`  
   - `at` (daemon must be running)  

   ```bash
   # Debian/Ubuntu
   sudo apt update
   sudo apt install tcpdump at

   # RHEL/CentOS
   sudo yum install tcpdump at
   ```

4. **SELinux/AppArmor** (if enabled) should allow `tcpdump` to write to `/var/log/outbound_collector/`.  

---

## Directory Structure

After setup, the repository (and local machine) will have:

```
.
├── README.md
├── outbound_ip_collector.sh         # Main setup script
└── /var/log/outbound_collector/     # (created at runtime)
    ├── conn-all-YYYYMMDDHHMM.pcap   # Hourly rotating PCAP files (up to 24)
    ├── unique_ips.txt               # Cumulative list of all unique destination IPs
    ├── outbound_ip_collector.log    # Log file for captures & extraction runs
    └── extract_unique_ips.sh        # Helper script scheduled via at
```

---

## Installation & Setup

1. **Clone or download this repository** onto your Linux host:
   ```bash
   git clone https://github.com/krishz-kishore/outbound-ip-collector.git
   cd outbound-ip-collector
   ```

2. **Make the main script executable**:
   ```bash
   sudo chmod +x outbound_ip_collector.sh
   ```

3. **Run the setup script**:
   ```bash
   sudo ./outbound_ip_collector.sh
   sudo chmod +x /usr/local/bin/extract_unique_ips.sh
   ```

4. **Verify initial setup**:
   - Ensure `tcpdump` is running:
     ```bash
     ps aux | grep '[t]cpdump'
     ```
   - Check that `/var/log/outbound_collector/` exists and is writable:
     ```bash
     ls -ld /var/log/outbound_collector
     ```

---

## Usage

Once installed, everything runs automatically.

To manually extract IPs:
```bash
sudo /usr/local/bin/extract_unique_ips.sh
```

To view collected unique destination IPs:
```bash
sudo cat /var/log/outbound_collector/unique_ips.txt
```

---

## How It Works

1. **Setup Script**
   - Prompts for interface
   - Creates `/var/log/outbound_collector/`
   - Starts `tcpdump` with `-G 3600 -W 24` (rotates every hour, max 24 files)
   - Schedules extract script every 12 hours via `at`

2. **Extract Script**
   - Runs every 12 hours
   - Scans PCAPs modified in last 12 hours
   - Extracts destination IPs, ports, protocol, and packet size
   - Updates `unique_ips.txt` with deduplicated IPs and additional details

---

## License

This project is open-source and free to use.
