from parsers import system_parser, apache_parser, firewall_parser, json_parser

SAMPLE_SIZE = 10           # how many non-empty lines to inspect
CONFIDENCE_THRESHOLD = 0.5  # a format must explain at least half the sample

# Order here also acts as the tie-breaker if two formats ever score
# exactly equally (the first one listed wins).
PARSER_CANDIDATES = {
    "apache": apache_parser.parse_line,
    "system": system_parser.parse_line,
    "firewall": firewall_parser.parse_line,
    "json": json_parser.parse_line,
}


def _read_sample_lines(filepath, max_lines=SAMPLE_SIZE):
    sample_lines = []
    with open(filepath, "r") as file:
        for line in file:
            if not line.strip():
                continue
            sample_lines.append(line)
            if len(sample_lines) >= max_lines:
                break
    return sample_lines


def detect_format(filepath):
    """
    Inspects the content of a handful of lines from the file and
    returns "system", "apache", "firewall", "json", or "unknown".
    """
    sample_lines = _read_sample_lines(filepath)

    if not sample_lines:
        return "unknown"

    total = len(sample_lines)

    scores = {}
    for name, parse_line in PARSER_CANDIDATES.items():
        matches = sum(1 for line in sample_lines if parse_line(line) is not None)
        scores[name] = matches / total

    best_format = max(scores, key=scores.get)
    best_ratio = scores[best_format]

    if best_ratio >= CONFIDENCE_THRESHOLD:
        return best_format

    return "unknown"