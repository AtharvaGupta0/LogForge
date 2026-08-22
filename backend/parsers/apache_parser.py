import re

pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)'

with open("samples/apache.log", "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            method = match.group("method")
            path = match.group("path")

            normalized_log = {
                "timestamp": match.group("timestamp"),
                "hostname": None,
                "source": "apache",

                "source_ip": match.group("ip"),
                "destination_ip": None,

                "protocol": match.group("protocol"),
                "action": None,
                "status_code": int(match.group("status")),

                "message": f"{method} {path}",

                "raw_log": line.rstrip("\n"),

                "extra_fields": {
                    "method": method,
                    "path": path,
                    "response_size": int(match.group("size")),
                }
            }
            print(normalized_log)
        else:
            print("Skipping malformed line:", line)