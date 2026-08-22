import re

PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+)'
)


def parse_line(line):
    """
    Attempt to parse one Apache access log line into the universal
    schema. Returns the normalized dict on success, or None if the
    line doesn't match this format.
    """
    match = PATTERN.search(line)
    if not match:
        return None

    method = match.group("method")
    path = match.group("path")

    return {
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
            "response_size": int(match.group("size"))
        }
    }