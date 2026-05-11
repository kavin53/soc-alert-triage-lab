def print_brute_force_alerts(alerts):
    print("\n== BRUTE FORCE ALERTS ==")

    if len(alerts) == 0:
        print("No brute force alerts found.")


    for alert in alerts:
        print("Alert name:", alert["alert_name"])
        print("Source IP:", alert["source_ip"])
        print("Attempts:", alert["attempts"])
        print("Window start:", alert["window_start"])
        print("Window end:", alert["window_end"])
        print("Severity:", alert["severity"])
        print()
    

def print_compromise_alerts(alerts):
    print("\n== COMPROMISE ALERTS ==")

    if len(alerts) > 0:
        for alert in alerts:
            print("Alert name:", alert["alert_name"])
            print("Source IP:", alert["source_ip"])
            print("User:", alert["user"])
            print("Failed attempts before success:", alert["failed_attempts_before_success"])
            print("Success time:", alert["success_time"])
            print("Severity:", alert["severity"])
            print("Reason:", alert["reason"])

            print("\nFailed evidence:")
            for evidence in alert["failed_evidence"]:
                print(" ", evidence)

            print("\nSuccess evidence:")
            print(" ", alert["success_evidence"])
            print()
    else:
        print("No compromise alerts found.")
