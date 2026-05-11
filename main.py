from utils.parser import parse_log_line
from utils.event_filters import filter_events_by_type
from utils.alert_printer import *
from detections.brute_force import detect_time_window_bruteforce
from detections.success_after_failures import detect_success_after_failures

HIGH_RISK = 5
TIME_WINDOW_MINUTES = 5
TEST_IP = "10.0.0.50"

parsed_events = []

with open("logs/auth.log", "r") as file:
    for line in file:
        parsed_event = parse_log_line(line)
        parsed_events.append(parsed_event)


failed_login_events = filter_events_by_type(parsed_events, "failed_login")
login_success_events = filter_events_by_type(parsed_events, "login_success")


brute_force_alerts = detect_time_window_bruteforce(
    failed_login_events,
    threshold = HIGH_RISK,
    time_window_minutes=TIME_WINDOW_MINUTES
)


compromise_alerts = detect_success_after_failures(
    failed_login_events,
    login_success_events,
    threshold=HIGH_RISK
)

#### Brute force alerts
brute_force = print_brute_force_alerts(brute_force_alerts)

##### Compromise alerts
compromise = print_compromise_alerts(compromise_alerts)




