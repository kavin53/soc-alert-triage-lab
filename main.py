def parse_log_line(line):
    event ={}

    fields = line.strip().split()

    for field in fields:
        if "=" in field:
            key,value = field.split("=",1)
            event[key] = value

    return event

parsed_events =[]

with open("logs/auth.log","r") as file:
    for line in file:
        parsed_event = parse_log_line(line)
        parsed_events.append(parsed_event)

print("\n == Parsed Events ==")


for event in parsed_events:
    print(event)