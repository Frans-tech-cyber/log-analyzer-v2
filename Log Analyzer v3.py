from datetime import datetime, timedelta


def analyze_logs(file_path, threshold=3, time_window=5):

    """
    Analyze system logs for suspicious activity including:
    - Error spikes
    - Password spraying
    - Unauthorized access attempts
    - Success-after-failure compromise patterns
    """

    # =========================
    # DATA STRUCTURES
    # =========================
    ip_errors = {}
    error_messages = {}
    username_attempts = {}
    ip_history = {}

    # Counters
    error_count = 0
    info_count = 0
    warning_count = 0
    failed_count = 0

    # =========================
    # PARSING PHASE
    # =========================
    with open(file_path, 'r') as file:
        for line in file:

            parts = line.strip().split(',')
            if len(parts) != 4:
                continue

            time_str, ip, severity, message = parts

            try:
                time_obj = datetime.strptime(time_str, "%H:%M")
            except ValueError:
                continue

            message_lower = message.lower()

            # -------------------------
            # LEVEL COUNTERS
            # -------------------------
            if severity == "ERROR":
                error_count += 1
                ip_errors.setdefault(ip, []).append(time_obj)

                error_messages.setdefault(message, {"count": 0, "ips": set()})
                error_messages[message]["count"] += 1
                error_messages[message]["ips"].add(ip)

            elif severity == "INFO":
                info_count += 1

            elif severity == "WARNING":
                warning_count += 1

            # -------------------------
            # PASSWORD SPRAY DETECTION
            # -------------------------
            if "failed login" in message_lower:
                failed_count += 1

                if ":" in message:
                    username = message.split(":")[-1].strip()
                    username_attempts.setdefault(username, set()).add(ip)

            # -------------------------
            # IP HISTORY STORAGE (V3 ENGINE)
            # -------------------------
            ip_history.setdefault(ip, []).append({
                "time": time_obj,
                "severity": severity,
                "message": message
            })

    # =========================
    # REPORT SECTION
    # =========================
    print("\n--- LOG ANALYSIS REPORT ---\n")
    print(f"Total ERROR entries: {error_count}")
    print(f"Total INFO entries: {info_count}")
    print(f"Total WARNING entries: {warning_count}")
    print(f"Total FAILED login attempts: {failed_count}")

    print("\n--- IP ERROR SUMMARY ---\n")
    for ip, times in ip_errors.items():
        print(f"{ip} -> {len(times)} errors")

    print("\n--- ERROR MESSAGES ---\n")
    for message, data in error_messages.items():
        print(f"{message} -> {data['count']} occurrences from IPs: {data['ips']}")

    # =========================
    # ALERTS SECTION
    # =========================
    print("\n--- ALERTS ---\n")

    # -------------------------
    # ERROR SPIKE DETECTION
    # -------------------------
    print(".... Error spikes ....")
    for ip, times in ip_errors.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= timedelta(minutes=time_window):
                print(f"ALERT: {ip} has {threshold}+ errors within {time_window} minutes.")
                break

    # -------------------------
    # SUSPICIOUS MESSAGE DETECTION
    # -------------------------
    print(".... Suspicious messages ....")
    for message, data in error_messages.items():
        if "unauthorized access" in message.lower() or "failed login" in message.lower():
            print(f"ALERT: Suspicious message '{message}' from IPs: {data['ips']}")

    # -------------------------
    # PASSWORD SPRAY DETECTION
    # -------------------------
    print(".... Password spraying detection ....")
    for username, ips in username_attempts.items():
        if len(ips) >= 3:
            print(f"ALERT: Password spraying detected for user '{username}' from IPs: {ips}")

    # -------------------------
    # V3: SUCCESS AFTER FAILURE DETECTION
    # -------------------------
    print(".... IP history analysis (V3) ....")

    for ip, events in ip_history.items():

        # sort by time (important for SOC logic)
        events.sort(key=lambda x: x["time"])

        for i in range(len(events)):

            msg_i = events[i]["message"].lower()

            if "failed login" in msg_i:

                failed_before_success = 1
                start_time = events[i]["time"]

                for j in range(i + 1, len(events)):

                    time_diff = events[j]["time"] - start_time

                    if time_diff > timedelta(minutes=time_window):
                        break

                    msg_j = events[j]["message"].lower()

                    if "failed login" in msg_j:
                        failed_before_success += 1

                    elif "user login successful" in msg_j:
                        if failed_before_success >= threshold:
                            print(
                                f"ALERT: {ip} had {failed_before_success} failed logins "
                                f"followed by success within {time_window} minutes."
                            )
                        break


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    analyze_logs("sample_logs.txt")
