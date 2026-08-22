import re

# Matches a leading ISO-8601 UTC timestamp, e.g. "2026-08-22T10:16:04Z"
TIMESTAMP_PATTERN = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)')

# Matches any KEY=value pair, e.g. "SRC=192.168.1.45"
FIELD_PATTERN = re.compile(r'(\w+)=(\S+)')

REQUIRED_FIELDS = {"SRC", "DST", "SPT", "DPT", "PROTO", "ACTION"}


def parse_line(line):
    """
    Attempt to parse one firewall log line (our supported
    key=value format) into the universal schema. Returns the
    normalized dict on success, or None if the line doesn't match
    this format or is missing/invalid required fields.
    """
    stripped = line.strip()
    if not stripped:
        return None

    timestamp_match = TIMESTAMP_PATTERN.match(stripped)
    if not timestamp_match:
        return None

    timestamp = timestamp_match.group("timestamp")
    remainder = stripped[timestamp_match.end():]

    fields = dict(FIELD_PATTERN.findall(remainder))

    if not REQUIRED_FIELDS.issubset(fields.keys()):
        return None

    try:
        source_port = int(fields["SPT"])
        destination_port = int(fields["DPT"])
    except ValueError:
        return None

    source_ip = fields["SRC"]
    destination_ip = fields["DST"]
    protocol = fields["PROTO"]
    action = fields["ACTION"]

    message = f"{protocol} {source_ip}:{source_port} -> {destination_ip}:{destination_port} {action}"

    return {
        "timestamp": timestamp,
        "hostname": None,
        "source": "firewall",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "action": action,
        "status_code": None,
        "message": message,
        "raw_log": line.rstrip("\n"),
        "extra_fields": {
            "source_port": source_port,
            "destination_port": destination_port,
        }
    }