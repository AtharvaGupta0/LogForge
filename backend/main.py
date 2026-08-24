import sys

from detector import detect_format
from parsers import system_parser, apache_parser, firewall_parser, json_parser

PARSERS = {
    "system": system_parser.parse_line,
    "apache": apache_parser.parse_line,
    "firewall": firewall_parser.parse_line,
    "json": json_parser.parse_line,
}


def main():
    if len(sys.argv) != 2:
        print("Usage: python backend/main.py <path-to-log-file>")
        return

    filepath = sys.argv[1]

    detected = detect_format(filepath)
    print(f"Detected format: {detected}")

    if detected == "unknown":
        print("Unsupported or unrecognised log format.")
        return

    parse_line = PARSERS[detected]

    parsed_count = 0
    failed_count = 0

    with open(filepath, "r") as file:
        for line in file:
            if not line.strip():
                continue

            result = parse_line(line)
            if result is not None:
                print(result)
                parsed_count += 1
            else:
                failed_count += 1

    print()
    print(f"Parsed: {parsed_count}")
    print(f"Failed: {failed_count}")


if __name__ == "__main__":
    main()