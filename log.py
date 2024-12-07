import re
import csv
from collections import defaultdict

# Function to parse the log file and extract data
def process_log_file(file_path):
    ip_requests = defaultdict(int)  # To count requests per IP
    endpoint_requests = defaultdict(int)  # To count requests per endpoint
    failed_login_attempts = defaultdict(int)  # To track failed login attempts
    failed_login_threshold = 10  # Default threshold for suspicious activity

    # Regular expression to parse the log lines
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?:GET|POST) (?P<endpoint>/\S*) .*?" (?P<status>\d{3}) .*?(?P<message>Invalid credentials)?'
    )

    # Read the log file line by line
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')  # Extract IP address
                endpoint = match.group('endpoint')  # Extract endpoint
                status = int(match.group('status'))  # Extract HTTP status code
                message = match.group('message')  # Extract error message if present

                # Count total requests per IP
                ip_requests[ip] += 1

                # Count total requests per endpoint
                endpoint_requests[endpoint] += 1

                # Track failed login attempts based on status code and error message
                if status == 401 and message == "Invalid credentials":
                    failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts, failed_login_threshold


# Function to write the results to a CSV file
def write_to_csv(ip_requests, endpoint_requests, suspicious_ips, file_name):
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_requests.items():
            writer.writerow([endpoint, count])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


# Main function
def main():
    log_file = 'sample.log'  # Input log file
    output_csv = 'log_analysis_results.csv'  # Output CSV file

    # Process the log file
    ip_requests, endpoint_requests, failed_login_attempts, threshold = process_log_file(log_file)

    # Sort and display IP requests
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    print("IP Address Requests:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    # Identify the most accessed endpoint
    most_accessed = max(endpoint_requests.items(), key=lambda x: x[1])
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Write results to a CSV file
    write_to_csv(ip_requests, endpoint_requests, suspicious_ips, output_csv)
    print(f"\nResults saved to {output_csv}")


if __name__ == "__main__":
    main()
