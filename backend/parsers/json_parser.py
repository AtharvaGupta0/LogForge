import json
# These are the fields shared by every LogForge parser.
UNIVERSAL_FIELDS = {
    "timestamp",
    "hostname",
    "source",
    "source_ip",
    "destination_ip",
    "protocol",
    "action",
    "status_code",
    "message",
}
def parse_line(line):
    """
    Parse one JSON log line into the LogForge universal schema.
    Returns:
        dict -> if the line contains a valid JSON log object
        None -> if the line is invalid or does not look like a log
    """
    # Ignore empty lines
    if not line.strip():
        return None
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    # A log entry must be a JSON object/dictionary.
    # Things such as JSON arrays, strings or numbers are rejected.
    if not isinstance(data, dict):
        return None
    # Prevent arbitrary JSON such as {"hello": "world"}
    # from being treated as a valid log.
    #
    # A record must contain at least one useful log-related field.
    if not any(field in data for field in UNIVERSAL_FIELDS):
        return None
    # Preserve every field that isn't part of our universal schema.
    extra_fields = {
        key: value
        for key, value in data.items()
        if key not in UNIVERSAL_FIELDS
    }
    return {
        "timestamp": data.get("timestamp"),
        "hostname": data.get("hostname"),
        "source": data.get("source"),
        "source_ip": data.get("source_ip"),
        "destination_ip": data.get("destination_ip"),
        "protocol": data.get("protocol"),
        "action": data.get("action"),
        "status_code": data.get("status_code"),
        "message": data.get("message"),
        "raw_log": line.rstrip("\n"),
        "extra_fields": extra_fields
    }
