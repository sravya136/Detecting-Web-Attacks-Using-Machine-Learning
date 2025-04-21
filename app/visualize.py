import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st
import os
import time
import requests

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
    st.error("❌ No internet connection. Please check your network and try again.")
    st.stop()  # Stop the script if no internet is available

log_file = "./logs/traffic_logs.csv"

# ✅ Function to classify attacks
def classify_attack(packet_size):
    """Returns attack type based on packet size."""
    if packet_size > 1500:
        return "DDoS Attack"
    elif 500 <= packet_size <= 1500:
        return "SQL Injection"
    else:
        return "XSS / Brute Force"

# ✅ Function to load attack logs
def load_data():
    """Loads the log file into a DataFrame."""
    if os.path.exists(log_file):
        df = pd.read_csv(log_file)
        return df
    return pd.DataFrame(columns=["timestamp", "size", "anomaly"])

# ✅ Main Streamlit app
st.title("🚨 Web Attack Detection System")

# ✅ Create tabs for different functionalities
tab1, tab2 = st.tabs(["📊 Live Web Attack Classification & Alerts", "🚨 Real-Time Monitoring"])

# ✅ Tab 1: Live Web Attack Classification & Alerts
with tab1:
    st.header("📊 Live Web Attack Classification & Alerts")

    # Load data
    df = load_data()

    # ✅ Display total attack count
    total_attacks = df[df["anomaly"] == True].shape[0]
    st.metric(label="⚠️ Total Attacks Detected", value=total_attacks)

    # ✅ Check the most recent log entry
    if not df.empty:
        most_recent_entry = df.iloc[-1]  # Get the most recent entry

        # ✅ If the most recent entry is an attack, show alert
        if most_recent_entry["anomaly"]:
            attack_type = classify_attack(most_recent_entry['size'])
            st.warning(f"⚠️ {attack_type} Detected! ({most_recent_entry['size']} bytes)")
        else:
            # ✅ If the most recent entry is normal traffic, show no attack
            st.success("✅ No Attack Detected")

    # ✅ Plot graph only if attacks are detected
    if total_attacks > 0:
        # ✅ Count occurrences of each attack type
        df_anomalies = df[df['anomaly'] == True].copy()  # Use .copy() to avoid SettingWithCopyWarning
        df_anomalies['attack_type'] = df_anomalies['size'].apply(classify_attack)
        attack_counts = df_anomalies['attack_type'].value_counts()

        # ✅ Plot bar graph
        fig, ax = plt.subplots()
        attack_counts.plot(kind="bar", color=["red", "orange", "green"], ax=ax)
        ax.set_title("Attack Classification (Based on Packet Size)")
        ax.set_xlabel("Attack Type")
        ax.set_ylabel("Number of Occurrences")
        st.pyplot(fig)
    else:
        # ✅ Show message if no attacks are detected
        st.info("✅ No attacks detected in the logs. Nothing to visualize.")

# ✅ Tab 2: Real-Time Monitoring
with tab2:
    st.header("🚨 Real-Time Monitoring")

    # ✅ Auto-refresh every 10 seconds
    refresh_rate = 10

    # ✅ Main loop for real-time updates
    while True:
        df = load_data()

        # ✅ Check the most recent log entry
        if not df.empty:
            most_recent_entry = df.iloc[-1]  # Get the most recent entry

            # ✅ If the most recent entry is an attack, show alert
            if most_recent_entry["anomaly"]:
                st.warning(f"⚠️ Attack Detected at {most_recent_entry['timestamp']} (Size: {most_recent_entry['size']} bytes)")
            else:
                # ✅ If the most recent entry is normal traffic, show no attack
                st.success("✅ No Attack Detected")

        # ✅ Auto-refresh
        time.sleep(refresh_rate)
        st.rerun()  # Use st.rerun() instead of st.experimental_rerun()