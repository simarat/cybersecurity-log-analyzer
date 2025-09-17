import sys
import os
import io
from datetime import datetime
import streamlit as st

# ensure project root is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from log_analyzer.auth_log_parser import parse_auth_log
from log_analyzer.main import visualize_failed_attempts  # optional reuse

st.set_page_config(page_title="Cybersecurity Log Analyzer", layout="wide")
st.title("🔐 Cybersecurity Log Analyzer")

# config
BLOCKLIST_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "blocklist.txt"))
MIN_FAILURES = 5  # change threshold here if you want


def save_blocklist_ips(ips_with_counts, blocklist_path=BLOCKLIST_FILE):
    """
    Save IPs to blocklist file with a timestamp and count.
    Avoid duplicating the same IP entry on the same day.
    ips_with_counts: list of tuples (ip, count)
    """
    # ensure directory exists
    os.makedirs(os.path.dirname(blocklist_path), exist_ok=True)

    # read existing entries to avoid duplicates for same ip+date
    existing = set()
    if os.path.exists(blocklist_path):
        with open(blocklist_path, "r", encoding="utf-8") as f:
            for line in f:
                existing.add(line.strip())

    new_lines = []
    today_str = datetime.now().strftime("%Y-%m-%d")
    for ip, count in ips_with_counts:
        entry = f"{today_str} {ip} {count}"
        if entry not in existing:
            new_lines.append(entry)

    if new_lines:
        with open(blocklist_path, "a", encoding="utf-8") as f:
            for line in new_lines:
                f.write(line + "\n")

    return new_lines  # lines actually added


uploaded_file = st.file_uploader("Upload your auth log file", type=["log", "txt"])
use_sample = st.checkbox("Analyze sample_logs/logs.log instead of upload", value=False)

# analyze sample if user wants and file exists
if use_sample:
    sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "log_analyzer", "sample_logs", "logs.log"))
    if os.path.exists(sample_path):
        filepath = sample_path
        st.info(f"Using sample log: {sample_path}")
    else:
        st.error("Sample log not found.")
        filepath = None
else:
    filepath = None
    if uploaded_file is not None:
        # write uploaded content to temp file
        temp_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "uploaded.log"))
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        filepath = temp_path
        st.success("✅ Log file uploaded successfully!")

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
        st.subheader("⛔ Blocklist (IPs with >= {} failures)".format(MIN_FAILURES))
        blocklist = [(ip, len(timestamps)) for ip, timestamps in failed_attempts.items() if len(timestamps) >= MIN_FAILURES]
        if blocklist:
            for ip, count in blocklist:
                st.warning(f"{ip} — {count} attempts")
        else:
            st.write("No IPs meet blocklist criteria.")

        # Save blocklist to file button
        st.markdown("---")
        st.write("Save blocklisted IPs to a file (appends, avoids same-day duplicates):")
        if st.button("Save blocklist to file"):
            added = save_blocklist_ips(blocklist)
            if added:
                st.success(f"Saved {len(added)} new entries to `{BLOCKLIST_FILE}`.")
                st.write("Added entries:")
                for line in added:
                    st.code(line)
            else:
                st.info("No new entries added (duplicates for today or nothing to add).")

        # Show existing blocklist file (if exists) and offer download
        st.markdown("---")
        st.write("Existing blocklist file:")
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            st.text_area("blocklist.txt", content, height=200)
            # prepare bytes for download
            b = content.encode("utf-8")
            st.download_button("Download blocklist.txt", data=b, file_name="blocklist.txt", mime="text/plain")
        else:
            st.write("No blocklist file exists yet.")

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
