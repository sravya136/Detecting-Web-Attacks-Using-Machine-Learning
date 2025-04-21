import numpy as np
import joblib
import tensorflow as tf
from scapy.all import sniff
import csv
import os
import requests  # For internet connectivity check

# ✅ Function to check internet connectivity
def check_internet():
    """Checks if the internet is available."""
    try:
        # Try to access a reliable external server
        requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

# ✅ Check internet connectivity
if not check_internet():
    print("❌ No attack due to absence of internet.")
    exit()  # Stop the script if no internet is available

# ✅ Load trained model, scaler, and threshold
custom_objects = {"mse": tf.keras.losses.MeanSquaredError()}
model = tf.keras.models.load_model("./models/autoencoder_model.h5", custom_objects=custom_objects, compile=False)
model.compile()
scaler = joblib.load("./models/scaler.pkl")
threshold = joblib.load("./models/threshold.pkl")

log_file = "./logs/traffic_logs.csv"
os.makedirs("./logs", exist_ok=True)

if not os.path.exists(log_file):
    with open(log_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "size", "anomaly"])  # ✅ Ensure correct headers

def convert_feature(value):
    """Converts non-numeric packet features to float-compatible values."""
    if isinstance(value, bytes):
        return sum(value) % 256  # ✅ Convert bytes to a numeric value
    return value if isinstance(value, (int, float)) else 0  # ✅ Ensure all values are numeric

def process_packet(packet):
    """Processes incoming packets and detects anomalies."""
    try:
        # ✅ Extract features (Ensure 78 features match training data)
        features = [
            len(packet),  # ✅ Packet Size
            packet.time,  # ✅ Timestamp
            1 if 'TCP' in packet else 0,  # ✅ Protocol Type
            packet.ttl if hasattr(packet, "ttl") else 0,  # ✅ Time to Live (TTL)
            packet.window if hasattr(packet, "window") else 0,  # ✅ TCP Window Size
            packet.payload.load if hasattr(packet.payload, "load") else 0  # ✅ Payload Size
        ]

        # ✅ Convert all features to numeric values
        features = [convert_feature(f) for f in features]

        # ✅ Ensure exactly 78 features (Pad with 0 if needed)
        while len(features) < 78:
            features.append(0)

        # ✅ Convert to NumPy array and normalize
        features = np.array(features).reshape(1, -1)
        X_live = scaler.transform(features)

        # ✅ Make prediction
        recon = model.predict(X_live)
        mse = np.mean(np.power(X_live - recon, 10))

        is_anomaly = 1 if mse > threshold else 0  # ✅ Log as 1 or 0

        # ✅ Save to logs
        with open(log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([packet.time, len(packet), bool(is_anomaly)])  # ✅ Store as True (attack) or False (normal)

        # ✅ Show attack detection in required format
        if is_anomaly:
            print(f"⚠️ Attack Detected at {packet.time} (Size: {len(packet)})")
        else:
            print("✅ Normal Traffic")

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    """Starts capturing live packets."""
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()