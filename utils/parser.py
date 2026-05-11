def parse_log_line(line):
    event = {}

    clean_line = line.strip()
    event["raw_log"] = clean_line

    fields = clean_line.split()

    for field in fields:
        if "=" in field:
            key, value = field.split("=", 1)
            event[key] = value

    return event