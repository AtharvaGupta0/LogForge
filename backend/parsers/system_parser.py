import re

# A syslog timestamp always looks like: "Aug 21 22:44:33"
# (3-letter month, day, HH:MM:SS). Checking this shape — not just
# the slice's length — stops arbitrary text from being misread as
# a valid Linux log line during format detection.
TIMESTAMP_PATTERN = re.compile(r'^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}$')


def parse_line(line):
    """
    Attempt to parse one Linux/syslog line into the universal schema.
    Returns the normalized dict on success, or None if the line
    doesn't match this format.
    """
    try:
        timestamp = line[:15]
        remainder = line[16:]

        if not TIMESTAMP_PATTERN.match(timestamp):
            return None

        hostname, rest = remainder.split(" ", 1)
        source_part, message = rest.split(" ", 1)

        source = source_part.rstrip(":")

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "source": source,
            "source_ip": None,
            "destination_ip": None,
            "protocol": None,
            "action": None,
            "status_code": None,
            "message": message.rstrip("\n"),
            "raw_log": line.rstrip("\n"),
            "extra_fields": {}
        }
    except ValueError:
        return None