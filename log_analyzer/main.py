import re
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt  


def parse_auth_log(file_path):
    failed_attempts = defaultdict(list)
    pattern = r"(?P<datetime>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .* Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)"

    with open(file_path, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group("datetime")
                ip = match.group("ip")
                timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                failed_attempts[ip].append(timestamp)

    return failed_attempts


def print_summary(failed_attempts):
    print("\n--- Failed Login Summary ---")
    for ip, timestamps in failed_attempts.items():
        print(f"{ip}: {len(timestamps)} failed attempts")


def detect_brute_force(failed_attempts, threshold=5, interval=60):
    print("\n--- Suspicious Activity Report ---")
    for ip, timestamps in failed_attempts.items():
        timestamps.sort()
        for i in range(len(timestamps) - threshold + 1):
            if (timestamps[i + threshold - 1] - timestamps[i]).seconds <= interval:
                print(f"[ALERT] {ip} had {threshold}+ failed logins in {interval} seconds.")
                break


def generate_blocklist(failed_attempts, min_failures=5):
    print("\n--- Blocklist ---")
    for ip, timestamps in failed_attempts.items():
        if len(timestamps) >= min_failures:
            print(ip)


def visualize_failed_attempts(failed_attempts):
    ips = list(failed_attempts.keys())
    counts = [len(failed_attempts[ip]) for ip in ips]

    plt.bar(ips, counts, color="orange")
    plt.xlabel("IP Address")
    plt.ylabel("Failed Login Attempts")
    plt.title("Failed Login Attempts per IP")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    log_path = "sample_logs/logs.log"  
    failed_attempts = parse_auth_log(log_path)

    print_summary(failed_attempts)          
    detect_brute_force(failed_attempts)      
    generate_blocklist(failed_attempts)     
    visualize_failed_attempts(failed_attempts) 
