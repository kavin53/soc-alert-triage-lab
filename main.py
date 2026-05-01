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

failed_login_events = []

for event in parsed_events:
   
    if event["event"] == "failed_login":
        failed_login_events.append(event)

print("\n === Failed Login Events ===")

for event in failed_login_events:
    print (event)

print(f"\nTotal Failed Login Events: {len(failed_login_events)}"    )