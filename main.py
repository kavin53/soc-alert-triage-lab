ip_counts = {}

with open("logs/logs.txt","r") as file:
    for line in file:
        if "FAILED LOGIN" in line:
            parts = line.split("ip=")
            ip = parts[1].strip()

            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

print("== IP ATTEMPTS ==")
for ip , counts in ip_counts.items():
    print(f"{ip} -> {counts} attempts")

    
print("\n == ALERTS ==")

for ip , count in ip_counts.items():
    if count >=5:
        serverity = "HIGH"
    elif count >=3:
        serverity = "MEDIUM"
    else:
        serverity = "LOW"

    if serverity != "LOW":
        print(f"Alert : {ip} -> attempts: {count} -> severity: {serverity}")
