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
