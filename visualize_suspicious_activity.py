import os
import pandas as pd
import matplotlib.pyplot as plt

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
        if len(parts) == 4:
            ip, port, protocol, size = parts
            data.append((ip, port, protocol, int(size)))

# Create a DataFrame
df = pd.DataFrame(data, columns=["IP", "Port", "Protocol", "Size"])

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
