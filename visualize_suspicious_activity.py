#!/usr/bin/env python3
"""
visualize_suspicious_activity.py

Improved visualization and reporting for `outbound_ip_collector`.

Features:
 - CLI interface (input file, output dir, top N)
 - Robust parsing of `unique_ips.txt` entries
 - Optional reverse-DNS lookups (can be disabled for speed)
 - Optional GeoIP lookup if `geoip2` and a database are present
 - Generates multiple charts: top IPs, protocol distribution, top ports, traffic volume
 - Exports CSVs, an aggregated CSV, and a small HTML report containing images and a summary table

Usage:
  sudo python3 visualize_suspicious_activity.py --input /var/log/outbound_collector/unique_ips.txt --outdir /var/log/outbound_collector

Make sure to install dependencies (see `requirements.txt`).
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime
from typing import Optional, List, Dict, Tuple

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
except Exception as e:
    print("[ERROR] Missing Python dependencies. Please install requirements.txt:")
    print("  pip install -r requirements.txt")
    raise

import socket

IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


def parse_line(line: str) -> Optional[Tuple[str, str, str, int]]:
    """Parse a line from unique_ips.txt and return tuple (ip, port, protocol, size).

    Accept a few common formats (with whitespace separation). If the format is not recognized,
    return None.
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split()

    # Common forms previously used: ip port protocol size
    # Ensure parts length >= 1 and first is an IP
    if not parts:
        return None
    ip = parts[0]
    if not IP_RE.match(ip):
        # Try to find ip anywhere in line
        for p in parts:
            if IP_RE.match(p):
                ip = p
                break
        else:
            return None

    # Set defaults
    port = "unknown"
    protocol = "unknown"
    size = 0

    # Attempt to find port and size and protocol in the other tokens
    for token in parts[1:]:
        if token.isdigit() and port == "unknown":
            port = token
            continue
        # Size usually numeric but may be labelled: 'len' or 'length'
        if token.isdigit():
            size = int(token)
            continue
        # protocol check
        if token.isalpha() and len(token) <= 10:
            # Avoid picking '2021-11-03' or timestamps
            protocol = token
            continue

    return ip, port, protocol, size


def dns_lookup(ip: str, cache: Dict[str, str]) -> str:
    if ip in cache:
        return cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = "unknown"
    cache[ip] = name
    return name


def get_service_from_port(port: str) -> str:
    try:
        return socket.getservbyport(int(port))
    except Exception:
        return port


def make_output_dir(path: str):
    os.makedirs(path, exist_ok=True)


def top_n_barplot(series: pd.Series, output: str, title: str, xlabel: str = "", ylabel: str = "Count"):
    plt.figure(figsize=(10, 6))
    sns.set_style("whitegrid")
    ax = series.plot(kind="bar", color=sns.color_palette("Blues_d", len(series)))
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output)
    plt.close()


def pie_chart(series: pd.Series, output: str, title: str):
    plt.figure(figsize=(8, 6))
    fig, ax = plt.subplots(figsize=(8, 6))
    series.plot(kind='pie', autopct='%1.1f%%', startangle=140, ax=ax)
    ax.set_ylabel("")
    ax.set_title(title)
    plt.tight_layout()
    plt.savefig(output)
    plt.close()


def generate_html_report(outdir: str, top_ips_img: str, protocol_img: str, ports_img: str, size_img: str, aggregated_csv: str) -> str:
    html_path = os.path.join(outdir, "visualization_report.html")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    df = pd.read_csv(aggregated_csv)
    table_html = df.head(20).to_html(index=False, classes="dataframe table table-striped")
    html_content = f"""
    <html>
    <head><title>Outbound IP Collector - Visualization Report</title>
    <meta charset="utf-8">
    <style>body {{ font-family: Arial, sans-serif; margin: 20px; }} img {{ max-width: 100%; height: auto; }}</style>
    </head>
    <body>
    <h1>Outbound IP Collector - Visualization Report</h1>
    <p>Generated: {now}</p>
    <h2>Top Destination IPs</h2>
    <img src="{os.path.basename(top_ips_img)}" alt="Top IPs">
    <h2>Protocol Distribution</h2>
    <img src="{os.path.basename(protocol_img)}" alt="Protocol Distribution">
    <h2>Top Ports</h2>
    <img src="{os.path.basename(ports_img)}" alt="Top Ports">
    <h2>Traffic Size per IP (sum of packet sizes)</h2>
    <img src="{os.path.basename(size_img)}" alt="Size by IP">
    <h2>Aggregated IP Table</h2>
    {table_html}
    </body>
    </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_path


def main():
    parser = argparse.ArgumentParser(description="Visualize outbound IP traffic and summarize results.")
    parser.add_argument("-i", "--input", default="/var/log/outbound_collector/unique_ips.txt", help="Path to unique_ips.txt")
    parser.add_argument("-o", "--outdir", default="/var/log/outbound_collector", help="Output directory for images and CSVs")
    parser.add_argument("-n", "--top", default=10, type=int, help="Top N items to chart")
    parser.add_argument("--no-dns", action="store_true", help="Disable reverse DNS lookups (faster)")
    parser.add_argument("--no-seaborn", action="store_true", help="If seaborn isn't installed, fallback style")
    parser.add_argument("--only-ips", action="store_true", help="Generate only top IPs chart")
    args = parser.parse_args()

    input_file = args.input
    outdir = args.outdir
    top_n = args.top
    no_dns = args.no_dns
    no_seaborn = args.no_seaborn

    if no_seaborn:
        try:
            import matplotlib
            matplotlib.style.use('ggplot')
        except Exception:
            pass

    if not os.path.exists(input_file):
        print(f"[ERROR] Input file '{input_file}' not found.")
        sys.exit(1)

    make_output_dir(outdir)

    print("[INFO] Loading unique IP data and parsing lines...")
    records: List[Tuple[str, str, str, int]] = []
    skipped = 0
    with open(input_file, "r") as fh:
        for ln in fh:
            parsed = parse_line(ln)
            if parsed is None:
                skipped += 1
                continue
            records.append(parsed)

    if not records:
        print("[WARN] No records were parsed, exiting.")
        sys.exit(0)

    df = pd.DataFrame(records, columns=["IP", "Port", "Protocol", "Size"])

    print(f"[INFO] Parsed {len(df)} entries; skipped {skipped} malformed lines.")

    # Resolve DNS if enabled
    dns_cache: Dict[str, str] = {}
    if no_dns:
        df["DNS"] = "disabled"
    else:
        print("[INFO] Running reverse-DNS lookups (may take a while)...")
        df["DNS"] = df["IP"].apply(lambda ip: dns_lookup(ip, dns_cache))

    # Resolve service name from numeric port; retain port if not resolved
    df["ResolvedProtocol"] = df["Port"].apply(lambda p: get_service_from_port(p) if p and p != "unknown" else "unknown")

    # Aggregations
    df["TotalHits"] = df.groupby("IP")["IP"].transform("count")
    aggregated_df = df.groupby("IP").agg({
        "Port": lambda s: ",".join(sorted(set([str(x) for x in s if x not in (None, '', 'unknown')]))) or 'none',
        "ResolvedProtocol": lambda s: ",".join(sorted(set([str(x) for x in s if x not in (None, '', 'unknown')]))) or 'unknown',
        "DNS": "first",
        "Size": "sum",
        "TotalHits": "first",
    }).reset_index()

    # Sort aggregated df by TotalHits
    aggregated_df.sort_values(by="TotalHits", ascending=False, inplace=True)

    aggregated_csv = os.path.join(outdir, f"aggregated_detailed_table_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv")
    aggregated_df.to_csv(aggregated_csv, index=False)
    print(f"[INFO] Aggregated CSV written: {aggregated_csv}")

    if args.only_ips:
        # Only top IPs
        top_ips = aggregated_df.set_index('IP')['TotalHits'].head(top_n)
        top_img = os.path.join(outdir, f"top_ips_{top_n}.png")
        top_n_barplot(top_ips, top_img, f"Top {top_n} Destination IPs", xlabel="IP")
        print(f"[INFO] Top IP chart saved to {top_img}")
        sys.exit(0)

    # Top IPs
    top_ips = aggregated_df.set_index('IP')['TotalHits'].head(top_n)
    top_img = os.path.join(outdir, f"top_ips_{top_n}.png")
    top_n_barplot(top_ips, top_img, f"Top {top_n} Destination IPs", xlabel="IP")

    # Protocol distribution based on ResolvedProtocol
    proto_counts = aggregated_df['ResolvedProtocol'].value_counts()
    proto_img = os.path.join(outdir, "protocol_distribution.png")
    pie_chart(proto_counts, proto_img, "Protocol Distribution")

    # Top ports (aggregate from Port open values in aggregated table)
    # Create a Series of ports -> sum of TotalHits
    port_hits: Dict[str, int] = {}
    for _, row in aggregated_df.iterrows():
        ports = str(row['Port']).split(',') if row['Port'] else []
        for p in ports:
            if not p or p == 'none' or p == 'unknown':
                continue
            port_hits[p] = port_hits.get(p, 0) + int(row['TotalHits'])
    ports_s = pd.Series(port_hits, name='TotalHits').sort_values(ascending=False).head(top_n)
    ports_img = os.path.join(outdir, f"top_ports_{top_n}.png")
    if not ports_s.empty:
        top_n_barplot(ports_s, ports_img, f"Top {top_n} Destination Ports", xlabel="Port")
    else:
        ports_img = ""

    # Traffic size per IP
    size_series = aggregated_df.set_index('IP')['Size'].head(top_n)
    size_img = os.path.join(outdir, f"top_size_{top_n}.png")
    if not size_series.empty:
        top_n_barplot(size_series, size_img, f"Top {top_n} IPs by Traffic Size", xlabel='IP', ylabel='Bytes')
    else:
        size_img = ''

    # HTML report
    html_path = generate_html_report(outdir, top_img, proto_img, ports_img, size_img, aggregated_csv)
    print(f"[INFO] HTML report generated: {html_path}")
    print("[INFO] All images and CSVs are saved to the output dir.")


if __name__ == '__main__':
    main()
import os
import pandas as pd
import matplotlib.pyplot as plt
import socket

# Define paths
BASE_DIR = "/var/log/outbound_collector"
UNIQUE_IP_FILE = os.path.join(BASE_DIR, "unique_ips.txt")

# Check if the unique IP file exists
if not os.path.exists(UNIQUE_IP_FILE):
    print(f"[ERROR] {UNIQUE_IP_FILE} does not exist. Run the extraction script first.")
    exit(1)

# Load the unique IP data
print("[INFO] Loading unique IP data...")
data = []
with open(UNIQUE_IP_FILE, "r") as file:
    for line in file:
        parts = line.strip().split()
        if len(parts) >= 4:  # Ensure there are at least 4 parts
            ip = parts[0]
            port = parts[1] if parts[1].isdigit() else "unknown"
            protocol = parts[2] if parts[2].isalpha() else "unknown"
            size = parts[3] if parts[3].isdigit() else "0"
            try:
                data.append((ip, port, protocol, int(size)))
            except ValueError:
                print(f"[WARN] Skipping invalid line: {line.strip()}")
        else:
            print(f"[WARN] Skipping malformed line: {line.strip()}")

# Create a DataFrame
df = pd.DataFrame(data, columns=["IP", "Port", "Protocol", "Size"])

# Enhance data with DNS names and protocol from port numbers
def get_protocol_from_port(port):
    try:
        return socket.getservbyport(int(port))
    except (ValueError, OSError):
        return port if port.isdigit() else "unknown"

def get_dns_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "unknown"

print("[INFO] Enhancing data with DNS names and protocols...")
df["DNS"] = df["IP"].apply(get_dns_name)
df["Protocol"] = df["Port"].apply(get_protocol_from_port)

# Add a column for total hits per IP
df["Total Hits"] = df.groupby("IP")["IP"].transform("count")

# Save enhanced detailed table to a CSV file
detailed_table_path = os.path.join(BASE_DIR, "enhanced_detailed_table.csv")
df.to_csv(detailed_table_path, index=False)
print(f"[INFO] Enhanced detailed table saved to {detailed_table_path}")

# Group by IP and aggregate data to ensure unique IPs
print("[INFO] Aggregating data to ensure unique IPs...")
aggregated_df = df.groupby("IP").agg({
    "Port": "first",  # Take the first port for each IP
    "Protocol": "first",  # Take the first protocol for each IP
    "DNS": "first",  # Take the first DNS name for each IP
    "Size": "sum",  # Sum the sizes for each IP
    "Total Hits": "count"  # Count the occurrences of each IP
}).reset_index()

# Save the aggregated table to a CSV file
aggregated_table_path = os.path.join(BASE_DIR, "aggregated_detailed_table.csv")
aggregated_df.to_csv(aggregated_table_path, index=False)
print(f"[INFO] Aggregated detailed table saved to {aggregated_table_path}")

# Summarize the data
print("[INFO] Summarizing data...")
top_ips = df["IP"].value_counts().head(10)
top_protocols = df["Protocol"].value_counts()

# Plot the top IPs
plt.figure(figsize=(10, 6))
top_ips.plot(kind="bar", color="skyblue")
plt.title("Top 10 Destination IPs")
plt.xlabel("IP Address")
plt.ylabel("Frequency")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "top_ips.png"))
plt.close()

# Plot the protocol distribution
plt.figure(figsize=(8, 5))
top_protocols.plot(kind="pie", autopct="%1.1f%%", startangle=140, colors=["lightcoral", "gold", "lightgreen"])
plt.title("Protocol Distribution")
plt.ylabel("")
plt.tight_layout()
plt.savefig(os.path.join(BASE_DIR, "protocol_distribution.png"))
plt.close()

print("[INFO] Visualization complete. Check the output in:")
print(f"  - {os.path.join(BASE_DIR, 'top_ips.png')} (Top IPs)")
print(f"  - {os.path.join(BASE_DIR, 'protocol_distribution.png')} (Protocol Distribution)")
