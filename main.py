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

print("IP Failed Login Counts:")
for ip, count in ip_counts.items():
    print(ip ,"-> ", count)
