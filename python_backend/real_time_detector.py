import time
from collections import Counter

import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest


# =========================================================
# SETTINGS
# =========================================================

WINDOW_SECONDS = 5
BASELINE_WINDOWS = 12

# Isolation Forest:
# contamination represents the expected proportion of unusual data.
model = IsolationForest(
    n_estimators=150,
    contamination=0.10,
    random_state=42
)


# =========================================================
# PACKET STORAGE
# =========================================================

packets = []


def collect_packet(packet):
    """Store captured IP packets for the current time window."""

    if IP in packet:
        packets.append(packet)


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_features(packet_list, duration):
    """Convert captured packets into numerical traffic features."""

    if not packet_list:
        return None

    total_packets = len(packet_list)

    total_bytes = sum(
        len(packet)
        for packet in packet_list
    )

    tcp_count = sum(
        1 for packet in packet_list
        if TCP in packet
    )

    udp_count = sum(
        1 for packet in packet_list
        if UDP in packet
    )

    unique_sources = len(
        {
            packet[IP].src
            for packet in packet_list
            if IP in packet
        }
    )

    unique_destinations = len(
        {
            packet[IP].dst
            for packet in packet_list
            if IP in packet
        }
    )

    destination_ports = []

    for packet in packet_list:

        if TCP in packet:
            destination_ports.append(
                packet[TCP].dport
            )

        elif UDP in packet:
            destination_ports.append(
                packet[UDP].dport
            )

    unique_destination_ports = len(
        set(destination_ports)
    )

    packet_rate = (
            total_packets / duration
    )

    byte_rate = (
            total_bytes / duration
    )

    average_packet_size = (
            total_bytes / total_packets
    )

    tcp_ratio = (
            tcp_count / total_packets
    )

    udp_ratio = (
            udp_count / total_packets
    )

    return {
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "average_packet_size": average_packet_size,
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "unique_sources": unique_sources,
        "unique_destinations": unique_destinations,
        "unique_destination_ports":
            unique_destination_ports
    }


# =========================================================
# FEATURE COLUMNS
# =========================================================

FEATURE_COLUMNS = [
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "unique_sources",
    "unique_destinations",
    "unique_destination_ports"
]


# =========================================================
# MAIN PROGRAM
# =========================================================

print("=" * 70)
print("        INTELLIGUARD - REAL-TIME AI IDS")
print("=" * 70)

print(
    f"Collecting normal traffic baseline "
    f"for {BASELINE_WINDOWS} windows..."
)

print(
    "Use your computer normally during this time."
)

print("=" * 70)


# ---------------------------------------------------------
# BASELINE COLLECTION
# ---------------------------------------------------------

baseline_features = []


for window_number in range(
        1,
        BASELINE_WINDOWS + 1
):

    packets.clear()

    print(
        f"\nBaseline window "
        f"{window_number}/{BASELINE_WINDOWS}"
    )

    start_time = time.time()

    sniff(
        filter="ip",
        prn=collect_packet,
        store=False,
        timeout=WINDOW_SECONDS
    )

    duration = max(
        time.time() - start_time,
        0.001
    )

    features = extract_features(
        packets,
        duration
    )

    if features is not None:

        baseline_features.append(
            features
        )

        print(
            f"Packets: "
            f"{len(packets)} | "
            f"Packet rate: "
            f"{features['packet_rate']:.2f}/sec | "
            f"Bytes/sec: "
            f"{features['byte_rate']:.2f}"
        )

    else:

        print("No IP traffic captured.")


# ---------------------------------------------------------
# TRAIN AI
# ---------------------------------------------------------

if len(baseline_features) < 3:

    print(
        "\nNot enough baseline traffic."
    )

    print(
        "Use the computer normally and run "
        "the program again."
    )

    raise SystemExit


baseline_df = pd.DataFrame(
    baseline_features
)

X_baseline = baseline_df[
    FEATURE_COLUMNS
]

model.fit(X_baseline)


print("\n" + "=" * 70)
print("AI BASELINE TRAINING COMPLETE")
print("=" * 70)

print(
    f"Training windows: "
    f"{len(baseline_df)}"
)

print(
    "Starting live anomaly detection..."
)

print("Press Ctrl+C to stop.")

print("=" * 70)


# ---------------------------------------------------------
# LIVE DETECTION
# ---------------------------------------------------------

while True:

    packets.clear()

    start_time = time.time()

    sniff(
        filter="ip",
        prn=collect_packet,
        store=False,
        timeout=WINDOW_SECONDS
    )

    duration = max(
        time.time() - start_time,
        0.001
    )

    features = extract_features(
        packets,
        duration
    )

    if features is None:

        print(
            "\nNo IP traffic in this window."
        )

        continue


    feature_df = pd.DataFrame(
        [features]
    )

    X_live = feature_df[
        FEATURE_COLUMNS
    ]


    # 1 = normal
    # -1 = anomaly
    prediction = model.predict(X_live)[0]

    anomaly_score = model.decision_function(
        X_live
    )[0]


    if prediction == 1:

        label = "NORMAL"

    else:

        label = "SUSPICIOUS"


    timestamp = time.strftime(
        "%H:%M:%S"
    )


    print(
        f"\n[{timestamp}] "
        f"{label} | "
        f"Packets: {len(packets)} | "
        f"Packet rate: "
        f"{features['packet_rate']:.2f}/sec | "
        f"Bytes/sec: "
        f"{features['byte_rate']:.2f} | "
        f"Avg packet: "
        f"{features['average_packet_size']:.2f} bytes | "
        f"Anomaly score: "
        f"{anomaly_score:.4f}"
    )