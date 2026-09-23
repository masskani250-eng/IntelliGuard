import numpy as np
import threading
import time
import psutil

from collections import Counter
from flask import Flask, jsonify
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)


# =========================================================
# SETTINGS
# =========================================================

WINDOW_SECONDS = 5
BASELINE_WINDOWS = 24


# =========================================================
# GLOBAL VARIABLES
# =========================================================

model = None
score_threshold = 0.0

latest_result = {
    "status": "STARTING",
    "packet_rate": 0,
    "bytes_per_sec": 0,
    "average_packet_size": 0,
    "tcp_ratio": 0,
    "udp_ratio": 0,
    "unique_sources": 0,
    "unique_destinations": 0,
    "unique_ports": 0,
    "anomaly_score": 0,

    # New application / connection information
    "application": "Unknown",
    "pid": 0,
    "destination_ip": "Unknown",
    "destination_port": 0
}

packet_buffer = []


# =========================================================
# PACKET COLLECTION
# =========================================================

def collect_packet(packet):
    """Store captured IP packets."""

    if IP in packet:
        packet_buffer.append(packet)


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_features(packets, duration):
    """Convert captured packets into ML features."""

    if not packets:
        return None

    total_packets = len(packets)

    total_bytes = sum(
        len(packet)
        for packet in packets
    )

    tcp_count = sum(
        1
        for packet in packets
        if TCP in packet
    )

    udp_count = sum(
        1
        for packet in packets
        if UDP in packet
    )

    sources = set()
    destinations = set()
    ports = set()

    for packet in packets:

        sources.add(packet[IP].src)
        destinations.add(packet[IP].dst)

        if TCP in packet:
            ports.add(packet[TCP].dport)

        elif UDP in packet:
            ports.add(packet[UDP].dport)

    packet_rate = total_packets / duration

    bytes_per_sec = total_bytes / duration

    average_packet_size = total_bytes / total_packets

    tcp_ratio = tcp_count / total_packets

    udp_ratio = udp_count / total_packets

    unique_sources = len(sources)

    unique_destinations = len(destinations)

    unique_ports = len(ports)

    return [
        packet_rate,
        bytes_per_sec,
        average_packet_size,
        tcp_ratio,
        udp_ratio,
        unique_sources,
        unique_destinations,
        unique_ports
    ]


# =========================================================
# APPLICATION / DESTINATION DETECTION
# =========================================================

def get_connection_info(packets):
    """
    Best-effort mapping:
    captured network endpoint -> Windows process.
    """

    endpoint_counter = Counter()

    # Collect TCP/UDP destination endpoints
    for packet in packets:

        if IP not in packet:
            continue

        dst_ip = packet[IP].dst

        if TCP in packet:
            dst_port = int(packet[TCP].dport)
            endpoint_counter[(dst_ip, dst_port)] += 1

        elif UDP in packet:
            dst_port = int(packet[UDP].dport)
            endpoint_counter[(dst_ip, dst_port)] += 1

    # Nothing to match
    if not endpoint_counter:
        return {
            "application": "Unknown",
            "pid": 0,
            "destination_ip": "Unknown",
            "destination_port": 0
        }

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        connections = []

    # Build a map of active remote connections
    connection_map = {}

    for conn in connections:

        try:
            if not conn.pid:
                continue

            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = int(conn.raddr.port)

            key = (remote_ip, remote_port)

            if key not in connection_map:
                connection_map[key] = conn.pid

        except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
                AttributeError,
                ValueError,
                TypeError
        ):
            continue

    # Try the most frequently observed destination first
    for (destination_ip, destination_port), count in endpoint_counter.most_common():

        pid = connection_map.get(
            (destination_ip, destination_port)
        )

        if pid is None:
            continue

        application = "Unknown"

        try:
            application = psutil.Process(pid).name()

        except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
        ):
            application = "Unknown"

        return {
            "application": application,
            "pid": int(pid),
            "destination_ip": destination_ip,
            "destination_port": int(destination_port)
        }

    # If exact process mapping was not found,
    # still show the most common destination.
    destination_ip, destination_port = (
        endpoint_counter.most_common(1)[0][0]
    )

    return {
        "application": "Unknown",
        "pid": 0,
        "destination_ip": destination_ip,
        "destination_port": int(destination_port)
    }


# =========================================================
# AI MONITOR
# =========================================================

def ai_monitor():

    global model
    global score_threshold
    global latest_result

    print("=" * 70)
    print("          INTELLIGUARD REAL-TIME AI SERVICE")
    print("=" * 70)

    print("Learning normal network behaviour...")
    print("Please use your computer normally.")

    print("=" * 70)

    baseline = []


    # -----------------------------------------------------
    # COLLECT NORMAL TRAFFIC
    # -----------------------------------------------------

    for i in range(BASELINE_WINDOWS):

        packet_buffer.clear()

        print(
            f"Collecting baseline window "
            f"{i + 1}/{BASELINE_WINDOWS}..."
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
            packet_buffer,
            duration
        )

        if features is not None:

            baseline.append(features)

            print(
                f"Baseline {i + 1}/{BASELINE_WINDOWS} | "
                f"Packets: {len(packet_buffer)} | "
                f"Rate: {features[0]:.2f}/sec"
            )

        else:

            print(
                f"Baseline {i + 1}/{BASELINE_WINDOWS} | "
                f"No IP traffic"
            )


    # -----------------------------------------------------
    # CHECK BASELINE
    # -----------------------------------------------------

    if len(baseline) < 5:

        latest_result["status"] = "ERROR"

        print(
            "ERROR: Not enough normal traffic "
            "for AI training."
        )

        return


    # -----------------------------------------------------
    # TRAIN ISOLATION FOREST
    # -----------------------------------------------------

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42
    )

    model.fit(baseline)


    # -----------------------------------------------------
    # CREATE BASELINE THRESHOLD
    # -----------------------------------------------------

    baseline_scores = model.decision_function(
        baseline
    )

    score_threshold = np.percentile(
        baseline_scores,
        2
    )


    print("=" * 70)
    print("AI TRAINING COMPLETE")

    print(
        f"Baseline samples: {len(baseline)}"
    )

    print(
        f"AI threshold: {score_threshold:.4f}"
    )

    print("REAL-TIME AI DETECTION STARTED")

    print("=" * 70)


    # -----------------------------------------------------
    # CONTINUOUS REAL-TIME DETECTION
    # -----------------------------------------------------

    while True:

        packet_buffer.clear()

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
            packet_buffer,
            duration
        )

        if features is None:

            print(
                "No IP traffic in this window."
            )

            continue


        # -------------------------------------------------
        # AI PREDICTION
        # -------------------------------------------------

        score = float(
            model.decision_function(
                [features]
            )[0]
        )


        if score >= score_threshold:

            status = "NORMAL"

        else:

            status = "SUSPICIOUS"


        # -------------------------------------------------
        # APPLICATION INFORMATION
        # -------------------------------------------------

        connection_info = get_connection_info(
            packet_buffer
        )


        # -------------------------------------------------
        # UPDATE LIVE RESULT
        # -------------------------------------------------

        latest_result = {

            "status": status,

            "packet_rate": round(
                features[0],
                2
            ),

            "bytes_per_sec": round(
                features[1],
                2
            ),

            "average_packet_size": round(
                features[2],
                2
            ),

            "tcp_ratio": round(
                features[3],
                3
            ),

            "udp_ratio": round(
                features[4],
                3
            ),

            "unique_sources": int(
                features[5]
            ),

            "unique_destinations": int(
                features[6]
            ),

            "unique_ports": int(
                features[7]
            ),

            "anomaly_score": round(
                score,
                4
            ),

            # New information
            "application": connection_info["application"],

            "pid": connection_info["pid"],

            "destination_ip": connection_info["destination_ip"],

            "destination_port": connection_info["destination_port"]
        }


        # -------------------------------------------------
        # PRINT RESULT
        # -------------------------------------------------

        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"{status} | "
            f"Packets: {len(packet_buffer)} | "
            f"Rate: {features[0]:.2f}/sec | "
            f"Bytes/sec: {features[1]:.2f} | "
            f"Score: {score:.4f} | "
            f"App: {connection_info['application']} | "
            f"Destination: "
            f"{connection_info['destination_ip']}:"
            f"{connection_info['destination_port']}"
        )


# =========================================================
# HOME API
# =========================================================

@app.route("/")
def home():

    return (
        "IntelliGuard Real-Time "
        "AI Service is running!"
    )


# =========================================================
# LIVE STATUS API
# =========================================================

@app.route("/status")
def status():

    return jsonify(
        latest_result
    )


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    monitor_thread = threading.Thread(
        target=ai_monitor,
        daemon=True
    )

    monitor_thread.start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )