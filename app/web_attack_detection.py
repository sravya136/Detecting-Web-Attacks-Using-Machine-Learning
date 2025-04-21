import streamlit as st
import subprocess
import os
import pandas as pd
import re
import time
import signal
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
    st.error("❌ No attack due to absence of internet.")
    st.stop()  # Stop the script if no internet is available

st.title("🚨 Detecting Web Attacks Using Machine Learning ")

log_file = "./logs/traffic_logs.csv"

# ✅ Store session state variables
if "alert_msg" not in st.session_state:
    st.session_state.alert_msg = "✅ No recent attacks."

if "monitoring" not in st.session_state:
    st.session_state.monitoring = False

if "process" not in st.session_state:
    st.session_state.process = None  # Track the subprocess

# ✅ Define alert placeholder at the top
alert_placeholder = st.empty()

def check_for_alerts():
    """Checks logs for the latest attack and updates Streamlit UI."""
    if os.path.exists(log_file):
        df = pd.read_csv(log_file)

        # ✅ Ensure 'anomaly' column exists
        if 'anomaly' not in df.columns:
            st.error("⚠️ Log file is missing 'anomaly' column. Re-run detection.")
            st.stop()

        # ✅ Convert 'anomaly' column to boolean (Fix False Positives)
        df['anomaly'] = df['anomaly'].astype(bool)

        # ✅ Check if there are any attacks in the log file
        if df['anomaly'].any():
            # ✅ Get the most recent attack
            most_recent_attack = df[df['anomaly']].iloc[-1]
            st.session_state.alert_msg = f"🔍 Checking for attacks at {most_recent_attack['timestamp']}"
            st.session_state.attack_detected = True  # Set flag for attack detected
        else:
            st.session_state.alert_msg = "✅ No recent attacks."
            st.session_state.attack_detected = False  # Set flag for no attack detected

# ✅ Monitoring Options
st.subheader("📡 Monitoring Options")

detect_script = os.path.join("app", "detect_attacks.py")
visualize_script = os.path.join("app", "visualize.py")

# ✅ Start Live Traffic Monitoring
if st.button("🚀 Start Live Traffic Monitoring"):
    if st.session_state.process is None:  # Only start if not already running
        st.session_state.monitoring = True
        st.session_state.process = subprocess.Popen(["python", detect_script])
        st.success("✅ Live traffic monitoring started.")

# ✅ Stop Live Traffic Monitoring
if st.button("🛑 Stop Live Traffic Monitoring"):
    if st.session_state.process is not None:  # Only stop if a process is running
        st.session_state.process.terminate()  # Terminate the subprocess
        st.session_state.process = None
        st.session_state.monitoring = False
        st.success("🛑 Live traffic monitoring stopped.")

# ✅ Analyze Past Traffic Logs
st.subheader("📊 Analyze Past Traffic Logs")
if st.button("📊 View Logs"):
    subprocess.Popen(["streamlit", "run", visualize_script])

# ✅ URL Safety Check
st.subheader("🔗 URL Safety Check")

def is_valid_url(url):
    """Check if URL has a proper format."""
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
        r'(?::\d+)?'  # port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def contains_malicious_patterns(url):
    """Check for common web attack patterns in URL."""
    malicious_patterns = [
        r'(\bSELECT\b|\bDROP\b|\bUNION\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bEXEC\b)',  # SQLi
        r'(<script>|alert\(|onerror=|onload=)',  # XSS
        r'(phpmyadmin|wp-admin|\.env|config\.)',  # Sensitive paths
        r'(http:\/\/|https:\/\/).*@',  # Credentials in URL
        r'\.(exe|bat|sh|zip|rar)$'  # Suspicious extensions
    ]
    for pattern in malicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

url_input = st.text_input("Enter URL to analyze:")
if st.button("🔍 Check URL Safety"):
    if not url_input:
        st.warning("Please enter a URL to check")
    else:
        with st.spinner("Analyzing URL..."):
            time.sleep(1)  # Simulate analysis time
            
            if not is_valid_url(url_input):
                st.error("❌ Unsafe URL!")
            elif contains_malicious_patterns(url_input):
                st.error("🛑 Malicious patterns detected! Potential security risk!")
            else:
                st.success("✅ URL appears safe and well-formatted")
                st.balloons()

# ✅ Live attack alert refresh
if st.session_state.monitoring:
    while True:
        check_for_alerts()
        alert_placeholder.warning(st.session_state.alert_msg)
        st.toast(st.session_state.alert_msg, icon="⚠️")
        time.sleep(30)  # ✅ Refreshes the alert box, not the whole page