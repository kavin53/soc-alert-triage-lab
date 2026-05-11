from datetime import datetime


def detect_success_after_failures(
    failed_login_events,
    login_success_events,
    threshold=5
):
    failed_attempts_by_key = {}

    for event in failed_login_events:
        ip = event["ip"]
        user = event["user"]

        key = (ip, user)

        if key not in failed_attempts_by_key:
            failed_attempts_by_key[key] = []

        failed_attempts_by_key[key].append(event)

    compromise_alerts = []

    for success_event in login_success_events:
        success_ip = success_event["ip"]
        success_user = success_event["user"]
        success_time = datetime.fromisoformat(success_event["timestamp"])

        key = (success_ip, success_user)

        if key not in failed_attempts_by_key:
            continue

        failed_events = failed_attempts_by_key[key]
        failures_before_success = []

        for failed_event in failed_events:
            failed_time = datetime.fromisoformat(failed_event["timestamp"])

            if failed_time < success_time:
                failures_before_success.append(failed_event)

        if len(failures_before_success) >= threshold:
            alert = {
                "alert_name": "Successful Login After Failed Attempts",
                "source_ip": success_ip,
                "user": success_user,
                "failed_attempts_before_success": len(failures_before_success),
                "success_time": success_time,
                "severity": "CRITICAL",
                "reason": "Multiple failed login attempts were followed by a successful login from the same IP and user.",
                "failed_evidence": [
                    event["raw_log"] for event in failures_before_success
                ],
                "success_evidence": success_event["raw_log"]
            }

            compromise_alerts.append(alert)

    return compromise_alerts