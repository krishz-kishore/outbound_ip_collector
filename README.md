Outbound IP Collector
=====================

A simple solution to capture all outbound traffic from a Linux host, store hourly packet captures, and periodically extract unique destination IPs into a single file. All logs, PCAPs, and outputs are centralized in one directory for easy management.

Table of Contents
-----------------

*   Features
    
*   Prerequisites
    
*   Directory Structure
    
*   Installation & Setup
    
*   Usage
    
*   How It Works
    
*   Scripts & Components
    
*   Troubleshooting
    
*   License
    

Features
--------

*   **Continuous Packet Capture**• Runs tcpdump on a user-specified interface, rotating hourly and keeping the last 24 PCAP files.
    
*   **Centralized Storage**• All PCAPs, logs, and unique-IP output are stored under /var/log/outbound\_collector/.
    
*   **Automated Unique IP Extraction**• Every 12 hours, parses recent PCAPs to extract destination IPs, merges them into one deduplicated file.
    
*   **Self-Scheduling via at**• The extraction task re-enqueues itself every 12 hours using the at command—no crontab needed.
    
*   **Minimal Dependencies**• Only requires: tcpdump, at, and a standard Linux shell environment.
    

Prerequisites
-------------

1.  **Linux Host** (CentOS, Ubuntu, Debian, etc.)
    
2.  **Root (or sudo) access**
    
3.  \# Debian/Ubuntusudo apt updatesudo apt install tcpdump at# RHEL/CentOSsudo yum install tcpdump at
    
    *   tcpdump
        
    *   at (daemon must be running)
        
4.  **SELinux/AppArmor** (if enabled) should allow tcpdump to write to /var/log/outbound\_collector/.
    

Directory Structure
-------------------

After setup, the repository (and local machine) will have:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   .  ├── README.md  ├── outbound_ip_collector.sh         # Main setup script  └── /var/log/outbound_collector/     # (created at runtime)      ├── conn-all-YYYYMMDDHHMM.pcap   # Hourly rotating PCAP files (up to 24)      ├── unique_ips.txt               # Cumulative list of all unique destination IPs      ├── outbound_ip_collector.log    # Log file for captures & extraction runs      └── extract_unique_ips.sh        # Helper script scheduled via at   `

*   **outbound\_ip\_collector.sh**The main installer script you run once. Prompts for interface, creates directories, starts tcpdump, drops the helper, and schedules its first run for 12 hours later.
    
*   **/var/log/outbound\_collector/**All runtime artifacts: PCAPs, logs, and unique\_ips.txt.
    
*   **extract\_unique\_ips.sh**Periodically invoked (via at) every 12 hours to parse the last 12 hours of PCAPs, extract unique IPs, and update unique\_ips.txt.
    

Installation & Setup
--------------------

1.  git clone https://github.com/yourusername/outbound-ip-collector.gitcd outbound-ip-collector
    
2.  sudo chmod +x outbound\_ip\_collector.sh
    
3.  sudo ./outbound\_ip\_collector.sh
    
    *   You will be prompted to enter the network interface (e.g., eth0, ens5, etc.).
        
    *   The script will create /var/log/outbound\_collector/, start a background tcpdump (hourly-rotating, 24 files), drop the helper into /usr/local/bin/extract\_unique\_ips.sh, and schedule its first run for 12 hours later.
        
4.  **Verify initial setup**:
    
    *   ps aux | grep '\[t\]cpdump'
        
    *   ls -ld /var/log/outbound\_collector
        

Usage
-----

Once installed, everything runs automatically:

*   /var/log/outbound\_collector/conn-all-202505201400.pcap/var/log/outbound\_collector/conn-all-202505201500.pcap…
    
*   /var/log/outbound\_collector/unique\_ips.txt• A timestamped log of these runs is appended to:/var/log/outbound\_collector/outbound\_ip\_collector.log
    
*   sudo /usr/local/bin/extract\_unique\_ips.sh
    
*   sudo cat /var/log/outbound\_collector/unique\_ips.txt
    

How It Works
------------

1.  **outbound\_ip\_collector.sh**
    
    *   Prompts for the network interface.
        
    *   Creates /var/log/outbound\_collector/ (root:root, permissions 750).
        
    *   Uses nohup tcpdump ... -G 3600 -W 24 to rotate hourly PCAPs (up to 24 files).
        
    *   Drops /usr/local/bin/extract\_unique\_ips.sh, makes it executable.
        
    *   Schedules the first extraction for “now + 12 hours” using at.
        
2.  **extract\_unique\_ips.sh**
    
    *   Finds PCAPs in /var/log/outbound\_collector/ modified in the last 12 hours (-mmin -720).
        
    *   Runs tcpdump -nnr on each to print packet summaries.
        
    *   IP 10.0.1.100.51432 > 13.107.6.152.443: ...
        
    *   Writes those IPs to a temporary file, then merges with unique\_ips.txt (if it exists), sorts, and removes duplicates.
        
    *   Cleans up the temporary file.
        
    *   Re-schedules itself “now + 12 hours” via at, appending logs to outbound\_ip\_collector.log.
        
3.  **Directory Permissions & Best Practices**
    
    *   /var/log/outbound\_collector/ is owned by root:root with chmod 750, ensuring only root (or sudo) can read/write logs and PCAPs.
        
    *   PCAP files are automatically pruned after 24 hours due to -W 24.
        
    *   The extraction script cleans up its temporary output (/tmp/recent\_ips\_.txt).
        

Scripts & Components
--------------------

### 1\. outbound\_ip\_collector.sh

*   **Location**: Repository root
    
*   **Purpose**:
    
    1.  Prompt for interface
        
    2.  Create /var/log/outbound\_collector/
        
    3.  Start tcpdump (hourly rotation, 24 files)
        
    4.  Deploy extract\_unique\_ips.sh
        
    5.  Schedule first run via at
        

### 2\. /usr/local/bin/extract\_unique\_ips.sh

*   **Location**: Installed to /usr/local/bin/
    
*   **Purpose**:
    
    1.  Parses PCAPs from the last 12 hours in /var/log/outbound\_collector/
        
    2.  Extracts destination IPs, merges into unique\_ips.txt
        
    3.  Logs completion and reschedules itself in 12 hours
        

Troubleshooting
---------------

*   **“tcpdump: permission denied”**• Ensure you run tcpdump as root or via sudo.• Confirm that your chosen interface exists (e.g., ip link show).• Verify that /var/log/outbound\_collector/ is writable by root.
    
*   **No PCAP files appearing**• Check that tcpdump started successfully (ps aux | grep tcpdump).• Inspect /var/log/outbound\_collector/outbound\_ip\_collector.log for errors.• Ensure the interface name is correct and has traffic.
    
*   **Extraction script fails**• Manually run /usr/local/bin/extract\_unique\_ips.sh and watch for errors.• Confirm atd is running (sudo systemctl status atd).• Check that PCAP files exist and have read permissions.
    
*   sudo systemctl enable --now atd• List pending at jobs:atq• Remove or re-schedule as needed:atrm
    

License
-------

This project is released under the MIT License. Feel free to modify and distribute as needed.

> **Note:** This solution works on any Linux host where you want to capture and track outbound connections over time.
