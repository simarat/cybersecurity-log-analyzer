import re
from collections import defaultdict
from datetime import datetime

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
print("parse_auth_log is defined")
