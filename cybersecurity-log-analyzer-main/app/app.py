import sys
import os
import streamlit as st

# make sure the parent folder is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_analyzer.auth_log_parser import parse_auth_log
from log_analyzer.main import (
    print_summary,
    detect_brute_force,
    generate_blocklist,
    visualize_failed_attempts,
)

st.title("🔐 Cybersecurity Log Analyzer")

uploaded_file = st.file_uploader("Upload your auth log file", type=["log", "txt"])

if uploaded_file is not None:
    # save uploaded file temporarily
    temp_path = "uploaded.log"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success("✅ Log file uploaded successfully!")

    # parse log
    failed_attempts = parse_auth_log(temp_path)

    # show summary
    st.subheader("📊 Failed Login Summary")
    for ip, timestamps in failed_attempts.items():
        st.write(f"{ip}: {len(timestamps)} failed attempts")

    # detect brute force
    st.subheader("🚨 Suspicious Activity")
    for ip, timestamps in failed_attempts.items():
        timestamps.sort()
        for i in range(len(timestamps) - 4):  # threshold = 5
            if (timestamps[i + 4] - timestamps[i]).seconds <= 60:
                st.error(f"[ALERT] {ip} had 5+ failed logins in 60 seconds.")
                break

    # blocklist
    st.subheader("⛔ Blocklist")
    blocklist = [ip for ip, t in failed_attempts.items() if len(t) >= 5]
    if blocklist:
        for ip in blocklist:
            st.warning(ip)
    else:
        st.write("No IPs meet blocklist criteria.")

    # visualize
    st.subheader("📈 Visualization")
    if failed_attempts:
        import matplotlib.pyplot as plt

        ips = list(failed_attempts.keys())
        counts = [len(failed_attempts[ip]) for ip in ips]

        fig, ax = plt.subplots()
        ax.bar(ips, counts, color="orange")
        ax.set_xlabel("IP Address")
        ax.set_ylabel("Failed Login Attempts")
        ax.set_title("Failed Login Attempts per IP")
        plt.xticks(rotation=45)
        st.pyplot(fig)
