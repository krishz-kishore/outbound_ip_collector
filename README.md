# Wazuh Outbound IP Collector

A simple solution to capture all outbound traffic from a Wazuh server (or any Linux host), store hourly packet captures, and periodically extract unique destination IPs into a single file. All logs, PCAPs, and outputs are centralized in one directory for easy management.

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
