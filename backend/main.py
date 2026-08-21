with open("samples/system.log", "r") as file:
    for line in file:
        try:
            timestamp = line[:15]
            remainder = line[16:]
            hostname, rest = remainder.split(" ", 1)
            source_part, message = rest.split(" ", 1)
            source = source_part.rstrip(":")
            normalized_log = {
                "timestamp": timestamp,
                "hostname": hostname,
                "source": source,
                "message": message,
                "raw_log": line,
            }
            print(normalized_log)
        except ValueError:
            print("Skipping malformed line:", line)