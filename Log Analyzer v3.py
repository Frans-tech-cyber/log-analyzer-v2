from datetime import datetime, timedelta


def analyze_logs(file_path, threshold=3, time_window=5):

    ip_errors = {}
    error_messages = {}
    username_attempts = {}

    error_count = 0
    info_count = 0
    warning_count = 0

    # Read and parse logs
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(',')

            if len(parts) != 4:
                continue

            time_str, ip, level, message = parts

            try:
                time_obj = datetime.strptime(time_str, "%H:%M")
            except ValueError:
                continue

            # Count log levels
            if level == "ERROR":
                error_count += 1

                ip_errors.setdefault(ip, []).append(time_obj)

                if message not in error_messages:
                    error_messages[message] = {
                        "count": 0,
                        "ips": set()
                    }

                error_messages[message]["count"] += 1
                error_messages[message]["ips"].add(ip)

            elif level == "INFO":
                info_count += 1

            elif level == "WARNING":
                warning_count += 1

            # Password spraying detection
            if "failed login" in message.lower():
                if ":" in message:
                    username = message.split(":")[-1].strip()
                    username_attempts.setdefault(username, set()).add(ip)

    # REPORT
    print("\n--- LOG ANALYSIS REPORT ---\n")
    print(f"Total ERROR entries: {error_count}")
    print(f"Total INFO entries: {info_count}")
    print(f"Total WARNING entries: {warning_count}")

    print("\n--- IP ERROR SUMMARY ---\n")
    for ip, times in ip_errors.items():
        print(f"{ip} -> {len(times)} errors")

    print("\n--- ERROR MESSAGES ---\n")
    for message, data in error_messages.items():
        print(f"{message} -> {data['count']} occurrences from IPs: {data['ips']}")

    print("\n--- ALERTS ---\n")

    # Time-based error spike detection
    for ip, times in ip_errors.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= timedelta(minutes=time_window):
                print(f"ALERT: {ip} has {threshold}+ errors within {time_window} minutes.")
                break

    # Suspicious message detection
    for message, data in error_messages.items():
        if "unauthorized access" in message.lower() or "failed login" in message.lower():
            print(f"ALERT: Suspicious message '{message}' from IPs: {data['ips']}")

    # Password spraying detection
    for username, ips in username_attempts.items():
        if len(ips) >= 3:
            print(f"ALERT: Password spraying detected for user '{username}' from IPs: {ips}")


if __name__ == "__main__":
    analyze_logs("sample_logs.txt")
