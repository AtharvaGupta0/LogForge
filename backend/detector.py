from parsers import system_parser, apache_parser

SAMPLE_SIZE = 10           # how many non-empty lines to inspect
CONFIDENCE_THRESHOLD = 0.5  # a format must explain at least half the sample


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
    returns "system", "apache", or "unknown".
    """
    sample_lines = _read_sample_lines(filepath)

    if not sample_lines:
        return "unknown"

    total = len(sample_lines)
    apache_matches = sum(
        1 for line in sample_lines if apache_parser.parse_line(line) is not None
    )
    system_matches = sum(
        1 for line in sample_lines if system_parser.parse_line(line) is not None
    )

    apache_ratio = apache_matches / total
    system_ratio = system_matches / total

    if apache_ratio >= CONFIDENCE_THRESHOLD and apache_ratio >= system_ratio:
        return "apache"
    if system_ratio >= CONFIDENCE_THRESHOLD and system_ratio > apache_ratio:
        return "system"

    return "unknown"