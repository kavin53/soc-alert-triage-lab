from datetime import datetime,timedelta 


MEDIUM_THRESHOLD = 3
HIGH_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5



def parse_log_line(line):
    event ={}

    fields = line.strip().split()

    for field in fields:
        if "=" in field:
            key,value = field.split("=",1)
            event[key] = value
    return event



def classify_severity(count):
    if count >= HIGH_THRESHOLD:
        return "high"
    elif count >= MEDIUM_THRESHOLD:
        return "medium"
    else:
        return "low"
    


parsed_events =[]

with open("logs/auth.log","r") as file:
    for line in file:
        parsed_event = parse_log_line(line)
        parsed_events.append(parsed_event)



failed_login_events = []

for event in parsed_events:
    if event["event"] == "failed_login":
        failed_login_events.append(event)



first_failed_event = failed_login_events[0]

failed_timestamps = []

for event in failed_login_events:
    if len(failed_login_events) > 0:
        timestamp_text = first_failed_event["timestamp"]
        timestamp_object = datetime.fromisoformat(timestamp_text)
        failed_timestamps.append(timestamp_object)
    else:
        print("No failed login events found.")



failed_times_by_ip = {}

for event in failed_login_events:
    ip = event["ip"]
    timestamp_text = event["timestamp"]
    timestamp_object = datetime.fromisoformat(timestamp_text)

    if ip not in failed_times_by_ip:
        failed_times_by_ip[ip] = []

    failed_times_by_ip[ip].append(timestamp_object)

print("\n== FAILED LOGIN TIMES BY IP ==")

for ip, timestamps in failed_times_by_ip.items():
    print(f"\nIP: {ip}")

    for timestamp in timestamps:
        print(f"  {timestamp}")



test_ip = "10.0.0.50"
timestamps = failed_times_by_ip[test_ip]
timestamps.sort()

window_start = timestamps[0]
window_end = window_start + timedelta(minutes = TIME_WINDOW_MINUTES)

print ("\n==TIME WINDOW TEST==")
print("Window start: ",window_start)
print("window end: ", window_end)


ip_counts = {}

for event in failed_login_events:
    ip = event["ip"]
    if ip in ip_counts:
        ip_counts[ip] += 1
    else:
        ip_counts[ip] = 1



alerts = []

for ip,count in ip_counts.items():
    severity = classify_severity(count)

    if severity != "low":
        alert = {
            "alert_name" : "possible brute force attack",
            "Source IP" : ip,
            "Attempts" : count,
            "Severity" : severity
        }

        alerts.append(alert)  

print("Failed login count per IP: ")



for ip,count in ip_counts.items():
    print(f"{ip}--> {count}")



for alert in alerts:
    print(
        f"{alert['alert_name']} | "
        f"Source IP: {alert['Source IP']} | "
        f"Attempts: {alert['Attempts']} | "
        f"Severity: {alert['Severity']}"
    )


