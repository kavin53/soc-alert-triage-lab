failed_count = 0

with open("logs/logs.txt", "r") as file:
    for line in file:
        if "failed" in line:
            failed_count += 1

print(f"Number of failed operations: {failed_count}")