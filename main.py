from datetime import datetime, timedelta
from utils.parser import parse_log_line
from detections.brute_force import detect_time_window_bruteforce

HIGH_RISK = 5

TIME_WINDOW_MINUTES = 5
TEST_IP = "10.0.0.50"

parsed_events = []

with open("logs/auth.log", "r") as file:
    for line in file:
        parsed_event = parse_log_line(line)
        parsed_events.append(parsed_event)


failed_login_events = []

for event in parsed_events:
    if event["event"] == "failed_login":
        failed_login_events.append(event)


login_success_events = []

for event in parsed_events:
    if event["event"] == "login_success":
        login_success_events.append(event)

#print("== Total login success events==")
#for event in login_success_events:
    #print(event["user"]," logged in at ", event["timestamp"], " from IP ", event["ip"])
#print("total login success events: ", len(login_success_events))


brute_force_alerts = detect_time_window_bruteforce(
    failed_login_events,
    threshold=HIGH_RISK,
    time_window_minutes=TIME_WINDOW_MINUTES
)

print("\n== BRUTE FORCE ALERTS ==")

if len(brute_force_alerts) > 0:
    for alert in brute_force_alerts:
        print("Alert name:", alert["alert_name"])
        print("Source IP:", alert["source_ip"])
        print("Attempts:", alert["attempts"])
        print("Window start:", alert["window_start"])
        print("Window end:", alert["window_end"])
        print("Severity:", alert["severity"])
        print()
else:
    print("No brute force alerts found.")

failed_attempts_by_key = {}

for event in failed_login_events:
    f_ip = event["ip"]
    f_user = event["user"]
   

    key = (f_ip,f_user)

    if key not in failed_attempts_by_key:
        failed_attempts_by_key[key] = []

    failed_attempts_by_key[key].append(event)

#print("\n== FAILED LOGIN TIMES BY IP AND USER ==")
#for key,timestamps in failed_attempts_by_key.items():
    #ip, user = key
    #print(f"\nIP: {ip}, User: {user}")
   # for timestamp in timestamps:
       # print(f" {timestamp}")
#print ("failed attempts : ",len(timestamps))


compromise_alerts = []

for event in login_success_events:
    s_user = event["user"]
    s_ip = event["ip"]
    success_timestamp = event["timestamp"]
    success_time = datetime.fromisoformat(success_timestamp)

    key = (s_ip, s_user)

    print(f"\n====Checking success login: IP={s_ip}, User={s_user}, Time={success_time}====")

    if key in failed_attempts_by_key:
        failed_events = failed_attempts_by_key[key]

        failures_before_success = []

        for failed_event in failed_events:

            failed_time = datetime.fromisoformat(failed_event["timestamp"])
            if failed_time < success_time:
                failures_before_success.append(failed_event)

        print("failures before success: ", len(failures_before_success))

        for failed_event in failures_before_success:
            print(" ",failed_event)

        if len(failures_before_success) >= HIGH_RISK:
            alert = {
                "alert_name": "successful login after failed attempts",
                "source_ip": s_ip,
                "user" : s_user,
                "attempts": len(failures_before_success),
                "success_time" : success_time,
                "severity": "critical",
                "reason" : "Multiple failed login attempts were followed by a successful login from the same IP and user."
            }
            compromise_alerts.append(alert)
    else:
        print("no previous failed attempts found for this ", s_ip ," + ", s_user)

    print("\n== COMPROMISE ALERTS ==")
    
    if len(compromise_alerts) > 0:
        for alert in compromise_alerts:
            print("Alert name:", alert["alert_name"])
            print("Source IP:", alert["source_ip"])
            print("User:", alert["user"])
            print("Failed attempts before success:", alert["attempts"])
            print("Success time:", alert["success_time"])
            print("Severity:", alert["severity"])
            print("Reason:", alert["reason"])
            print()
    else:
        print("No compromise alerts found.")




