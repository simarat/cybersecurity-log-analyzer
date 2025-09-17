import sys
import os
from datetime import datetime
import streamlit as st

# ensure project root is importable
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from log_analyzer.auth_log_parser import parse_auth_log
from log_analyzer.main import visualize_failed_attempts  # optional reuse

st.set_page_config(page_title="Cybersecurity Log Analyzer", layout="wide")
st.title("🔐 Cybersecurity Log Analyzer")

# config
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)
MIN_FAILURES = 5  # change threshold here if you want


def save_blocklist_ips(ips_with_counts, output_dir=OUTPUT_DIR):
    """
    Save IPs to a unique blocklist file with timestamp.
    Each save generates a new file, avoids overwriting previous blocklists.
    ips_with_counts: list of tuples (ip, count)
    """
    if not ips_with_counts:
        return None  # nothing to save

    os.makedirs(output_dir, exist_ok=True)

    # generate a timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    blocklist_path = os.path.join(output_dir, f"blocklist_{timestamp}.txt")

    today_str = datetime.now().strftime("%Y-%m-%d")
    with open(blocklist_path, "w", encoding="utf-8") as f:
        for ip, count in ips_with_counts:
            f.write(f"{today_str} {ip} {count}\n")

    return blocklist_path  # return the path of the saved file


# File upload / sample selection
uploaded_file = st.file_uploader("Upload your auth log file", type=["log", "txt"])
use_sample = st.checkbox("Analyze sample_logs/logs.log instead of upload", value=False)

filepath = None
if use_sample:
    sample_path = os.path.join(os.path.dirname(__file__), "log_analyzer", "sample_logs", "logs.log")
    if os.path.exists(sample_path):
        filepath = sample_path
        st.info(f"Using sample log: {sample_path}")
    else:
        st.error("Sample log not found.")
elif uploaded_file is not None:
    temp_path = os.path.join(os.path.dirname(__file__), "uploaded.log")
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    filepath = temp_path
    st.success("✅ Log file uploaded successfully!")

# Analyze log if available
if filepath:
    try:
        failed_attempts = parse_auth_log(filepath)

        st.subheader("📊 Failed Login Summary")
        if not failed_attempts:
            st.write("No failed-login records found.")
        else:
            for ip, timestamps in sorted(failed_attempts.items(), key=lambda x: -len(x[1])):
                st.write(f"{ip}: {len(timestamps)} failed attempts")

        # detect brute force alerts
        st.subheader("🚨 Suspicious Activity")
        alerts = []
        for ip, timestamps in failed_attempts.items():
            timestamps.sort()
            for i in range(max(0, len(timestamps) - (MIN_FAILURES - 1))):
                if (timestamps[i + MIN_FAILURES - 1] - timestamps[i]).total_seconds() <= 60:
                    alerts.append((ip, len(timestamps)))
                    st.error(f"[ALERT] {ip} had {MIN_FAILURES}+ failed logins in 60 seconds.")
                    break

        # generate blocklist (IPs with >= MIN_FAILURES total)
        st.subheader(f"⛔ Blocklist (IPs with >= {MIN_FAILURES} failures)")
        blocklist = [(ip, len(timestamps)) for ip, timestamps in failed_attempts.items() if len(timestamps) >= MIN_FAILURES]
        if blocklist:
            for ip, count in blocklist:
                st.warning(f"{ip} — {count} attempts")
        else:
            st.write("No IPs meet blocklist criteria.")

        # Save blocklist to file button
        st.markdown("---")
        st.write("Save blocklisted IPs to a file (each save creates a new file):")
        if st.button("Save blocklist to file"):
            saved_path = save_blocklist_ips(blocklist)
            if saved_path:
                st.success(f"Saved blocklist to `{saved_path}`.")
                with open(saved_path, "r", encoding="utf-8") as f:
                    st.text_area("Saved blocklist", f.read(), height=200)
                # offer download
                with open(saved_path, "rb") as f:
                    st.download_button(
                        "Download saved blocklist",
                        data=f,
                        file_name=os.path.basename(saved_path),
                        mime="text/plain"
                    )
            else:
                st.info("No IPs to save.")

        # Visualization (embedded)
        st.subheader("📈 Visualization")
        if failed_attempts:
            import matplotlib.pyplot as plt
            ips = [ip for ip, _ in sorted(failed_attempts.items(), key=lambda x: -len(x[1]))]
            counts = [len(failed_attempts[ip]) for ip in ips]
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.bar(ips, counts)
            ax.set_xlabel("IP Address")
            ax.set_ylabel("Failed Login Attempts")
            ax.set_title("Failed Login Attempts per IP")
            plt.xticks(rotation=45, ha='right')
            st.pyplot(fig)

    except Exception as e:
        st.error(f"Parsing failed: {e}")
