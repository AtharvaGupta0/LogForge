import re

pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)'

with open("samples/apache.log", "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            normalized_log = {
                "ip": match.group("ip"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "path": match.group("path"),
                "protocol": match.group("protocol"),
                "status": int(match.group("status")),
                "size": int(match.group("size")),
                "raw_log": line,
            }
            print(normalized_log)
        else:
            print("Skipping malformed line:", line)