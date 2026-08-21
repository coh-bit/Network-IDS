"""
generate_mock_dataset.py
==========================
Builds a mock network-traffic CSV with realistic Normal / DDoS_SYN_Flood /
Brute_Force / Port_Scan patterns, ordered by timestamp so attack sequences
are visible and contiguous -- useful for both RF (per-row features) and
LSTM (sequence windowing) later.

Run: python generate_mock_dataset.py
Output: mock_nids_traffic.csv
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)
rows = []

def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")

def rand_ip(prefix="192.168.1"):
    return f"{prefix}.{random.randint(2, 254)}"

def rand_ext_ip():
    return f"{random.randint(20, 220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# --------------------------------------------------------------------- #
# BLOCK 1: Normal traffic -- 15 rows, varied timing, ports 80/443/random
# --------------------------------------------------------------------- #
t = datetime(2026, 7, 16, 9, 0, 0)
for _ in range(15):
    t += timedelta(seconds=random.uniform(2, 15))
    rows.append([
        fmt(t), rand_ip(), rand_ext_ip(),
        random.choice([80, 443, 443, 80]),
        "TCP",
        random.randint(5, 60),
        random.randint(500, 20000),
        round(random.uniform(0.3, 8.0), 6),
        random.choice([0, 1]),
        1,
        0, "Normal",
    ])

# --------------------------------------------------------------------- #
# BLOCK 2: DDoS SYN Flood -- 12 rows, one victim, port 80, spoofed sources,
# packets arrive milliseconds apart, duration ~0, syn=1 ack=0
# --------------------------------------------------------------------- #
victim_ip = rand_ext_ip()
t += timedelta(seconds=random.uniform(3, 6))
for _ in range(12):
    t += timedelta(milliseconds=random.randint(5, 40))
    rows.append([
        fmt(t), rand_ext_ip(), victim_ip,   # spoofed/random source each time
        80, "TCP",
        random.randint(800, 5000),
        random.randint(40000, 300000),
        round(random.uniform(0.0, 0.02), 6),
        1, 0,
        1, "DDoS_SYN_Flood",
    ])

# --------------------------------------------------------------------- #
# BLOCK 3: Brute force -- 10 rows, one attacker, one victim, port 22,
# tight rhythmic intervals (~0.8s apart), low duration, mixed syn/ack
# (failed vs. successful login attempts)
# --------------------------------------------------------------------- #
attacker_ip = rand_ext_ip()
bf_target = rand_ip()
t += timedelta(seconds=random.uniform(4, 8))
for _ in range(10):
    t += timedelta(seconds=0.8 + random.uniform(-0.05, 0.05))
    failed = random.random() < 0.7
    rows.append([
        fmt(t), attacker_ip, bf_target,
        22, "TCP",
        random.randint(4, 12),
        random.randint(300, 1500),
        round(random.uniform(0.05, 0.4), 6),
        1,
        0 if failed else 1,
        1, "Brute_Force",
    ])

# --------------------------------------------------------------------- #
# BLOCK 4: Port scan -- 8 rows, one attacker, one victim, sequential
# ports climbing quickly, tiny packet counts, very short duration
# --------------------------------------------------------------------- #
scanner_ip = rand_ext_ip()
scan_target = rand_ip()
t += timedelta(seconds=random.uniform(3, 6))
start_port = 20
for i in range(8):
    t += timedelta(milliseconds=random.randint(30, 90))
    rows.append([
        fmt(t), scanner_ip, scan_target,
        start_port + i * random.randint(8, 14),
        "TCP",
        random.randint(1, 3),
        random.randint(40, 120),
        round(random.uniform(0.001, 0.02), 6),
        1, 0,
        1, "Port_Scan",
    ])

# --------------------------------------------------------------------- #
# Sort strictly by timestamp so the CSV reads as one continuous capture,
# then write out.
# --------------------------------------------------------------------- #
rows.sort(key=lambda r: r[0])

HEADER = [
    "timestamp", "source_ip", "dest_ip", "dest_port", "protocol",
    "packet_count", "byte_count", "duration", "flag_syn", "flag_ack",
    "label", "attack_type",
]

with open("mock_nids_traffic.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(HEADER)
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to mock_nids_traffic.csv")
print("Label breakdown:")
from collections import Counter
print(Counter(r[-1] for r in rows))
