import random
import pandas as pd


def generate_normal():
    return {
        "request_rate": round(random.uniform(0.5, 5.0), 2),
        "time_gap_ms": round(random.uniform(200, 1200), 2),
        "failed_logins": random.randint(0, 2),
        "packet_size_kb": round(random.uniform(1.0, 10.0), 2),
        "payload_entropy": round(random.uniform(2.0, 5.0), 2),
        "label": "Normal"
    }


def generate_attack():
    return {
        "request_rate": round(random.uniform(8.0, 25.0), 2),
        "time_gap_ms": round(random.uniform(20, 150), 2),
        "failed_logins": random.randint(4, 15),
        "packet_size_kb": round(random.uniform(0.1, 1.5), 2),
        "payload_entropy": round(random.uniform(6.0, 9.0), 2),
        "label": "Attack"
    }


data = []

for _ in range(2500):
    data.append(generate_normal())

for _ in range(2500):
    data.append(generate_attack())

random.shuffle(data)

df = pd.DataFrame(data)

df.to_csv("traffic_data.csv", index=False)

print("Dataset created successfully!")
print("Total records:", len(df))