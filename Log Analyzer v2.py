from datetime import datetime, timedelta

def analyze_logs(file_path, threshold=3, time_window=5):
    """
    Analyze log file for event distribution and suspicious activity.

    Args:
        file_path (str): Path to log file
        threshold (int): Number of events to trigger alert
        time_window (int): Time window in minutes
    """

    logs = []
    ip_errors = {}
    error_messages = {}

    error_count = 0
    info_count = 0
    warning_count = 0

    # 1. Read and parse logs (single pass)
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(',')

            # Skip malformed lines
            if len(parts) != 4:
                continue

            time_str, ip, level, message = parts

            try:
                time_obj = datetime.strptime(time_str, "%H:%M")
            except ValueError:
                continue

            logs.append((time_obj, ip, level, message))

            # Count log levels
            if level == "ERROR":
                error_count += 1

                # Track errors per IP
                ip_errors.setdefault(ip, []).append(time_obj)

                # Track error messages
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

    # 2. REPORT
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

    # 3. ALERTS
    print("\n--- ALERTS ---\n")

    # Time-based detection
    for ip, times in ip_errors.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= timedelta(minutes=time_window):
                print(f"ALERT: {ip} has {threshold}+ errors within {time_window} minutes.")
                break

    # Message-based detection
    for message, data in error_messages.items():
        if "unauthorized access" in message.lower() or "failed login" in message.lower():
            print(f"ALERT: Suspicious message '{message}' from IPs: {data['ips']}")


if __name__ == "__main__":
    analyze_logs("sample_logs.txt")