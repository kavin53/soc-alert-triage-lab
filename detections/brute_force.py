from datetime import datetime, timedelta

def detect_time_window_bruteforce(
        failed_login_events,
        threshold,
        time_window_minutes = 5
):
    failed_times_by_ip = {}
    
    for event in failed_login_events:
        ip = event["ip"]
        timestamp_text = event["timestamp"]
        timestamp_object = datetime.fromisoformat(timestamp_text)

        if ip not in failed_times_by_ip:
            failed_times_by_ip[ip] = []

        failed_times_by_ip[ip].append(timestamp_object)

        alerts = []

        for ip, timestamps in failed_times_by_ip.items():
            timestamps.sort()

            for start_index in range(len(timestamps)):
                window_start = timestamps[start_index]
                window_end = window_start + timedelta(minutes=time_window_minutes)

                attempts_in_window = []

                for current_time in timestamps:
                    if window_start <= current_time <= window_end:
                        attempts_in_window.append(current_time)

                if len(attempts_in_window) >= threshold:
                    alert = {
                        "alert_name": "Time-window Brute Force Attack",
                        "source_ip": ip,
                        "attempts": len(attempts_in_window),
                        "window_start": window_start,
                        "window_end": window_end,
                        "severity": "HIGH"
                    }

                    alerts.append(alert)
                    break

    return alerts