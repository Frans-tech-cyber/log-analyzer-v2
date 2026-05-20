from datetime import datetime, timedelta


def detect_brute_force_attempts(log_file, threshold=3, time_window=5):
    """
    Detect brute-force login attempts from a log file.
    
    Args:
        log_file (str): Path to log file
        threshold (int): Number of failed attempts to trigger alert
        time_window (int): Time window in minutes
    """

    failed_attempts = {}

    # 1. Parse logs
    with open(log_file, 'r') as f:
        for line in f:
            time_str, ip, status = line.strip().split(',')

            time_obj = datetime.strptime(time_str, "%H:%M")

            if status == "FAILED":
                if ip not in failed_attempts:
                    failed_attempts[ip] = []
                failed_attempts[ip].append(time_obj)

    # 2. Analyze patterns
    alerts = []

    for ip, times in failed_attempts.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            if times[i + threshold - 1] - times[i] <= timedelta(minutes=time_window):
                alerts.append((ip, times[i:i+threshold]))
                break

    # 3. Output report
    print("\n--- BRUTE FORCE DETECTION REPORT ---\n")

    if not failed_attempts:
        print("No failed login attempts detected.")
        return

    for ip, times in failed_attempts.items():
        print(f"{ip} -> {len(times)} failed attempts")

    print("\n--- ALERTS ---\n")

    if not alerts:
        print("No brute-force activity detected.")
    else:
        for ip, times in alerts:
            print(f"ALERT: Possible brute-force attack from {ip}")
            print(f"Times: {[t.strftime('%H:%M') for t in times]}")


if __name__ == "__main__":
    detect_brute_force_attempts("sample_logs.txt")