from datetime import datetime, timedelta

HIGH_RISK = 5
TIME_WINDOW_MINUTES = 5
TEST_IP = "10.0.0.50"



def parse_log_line(line):
    event = {}

    fields = line.strip().split()

    for field in fields:
        if "=" in field:
            key, value = field.split("=", 1)
            event[key] = value

    return event


parsed_events = []

with open("logs/auth.log", "r") as file:
    for line in file:
        parsed_event = parse_log_line(line)
        parsed_events.append(parsed_event)


failed_login_events = []

for event in parsed_events:
    if event["event"] == "failed_login":
        failed_login_events.append(event)


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


print("\n== TIME WINDOW TEST ==")

if TEST_IP in failed_times_by_ip:
    timestamps = failed_times_by_ip[TEST_IP]
    timestamps.sort()

    window_start = timestamps[0]
    window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

    print("Test IP:", TEST_IP)
    print("Window start:", window_start)
    print("Window end:", window_end)

    attempts_in_window = []

    for current_time in timestamps:
        if window_start <= current_time <= window_end:
            attempts_in_window.append(current_time)

    print("\n== ATTEMPTS INSIDE WINDOW ==")

    for attempt_time in attempts_in_window:
        print(attempt_time)

    print("Attempts inside window:", len(attempts_in_window))

    if len(attempts_in_window) >= HIGH_RISK:
        alert = {
            "alert_name": "Time-window Brute Force Attack",
            "source_ip": TEST_IP,
            "attempts": len(attempts_in_window),
            "window_start": window_start,
            "window_end": window_end,
            "severity": "HIGH"
        }

        print("\n== ALERT TRIGGERED ==")
        print("Alert name:", alert["alert_name"])
        print("Source IP:", alert["source_ip"])
        print("Attempts:", alert["attempts"])
        print("Window start:", alert["window_start"])
        print("Window end:", alert["window_end"])
        print("Severity:", alert["severity"])

    else:
        print("\n== NO ALERT ==")
        print("Reason: Attempts inside window did not reach threshold.")

else:
    print(f"No failed login events found for IP: {TEST_IP}")

