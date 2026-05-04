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

ip_counts = {}

for event in failed_login_events:
    ip = event["ip"]
    if ip in ip_counts:
        ip_counts[ip] += 1
    else:
        ip_counts[ip] = 1

print("Failed login count per IP: ")

for ip,count in ip_counts.items():
    print(f"{ip}--> {count}")

