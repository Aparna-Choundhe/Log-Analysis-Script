import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = 'sample.log'  # Path to the log file
OUTPUT_CSV = 'log_analysis_results.csv'  # Output CSV file name
FAILED_LOGIN_THRESHOLD = 10  # Threshold for suspicious activity

# Parse the log file and return the log lines
def parse_logs(log_file):
    with open(log_file, 'r') as file:
        logs = file.readlines()
    return logs

# Count requests per IP address
def count_requests_per_ip(logs):
    ip_counts = defaultdict(int)
    for line in logs:
        # Extract the IP address using regex
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_counts[ip] += 1
    return ip_counts

# Find the most frequently accessed endpoint
def find_most_frequent_endpoint(logs):
    endpoint_counts = defaultdict(int)
    for line in logs:
        # Extract the endpoint (path after the HTTP method)
        match = re.search(r'"(?:GET|POST|PUT|DELETE) (\S+)', line)
        if match:
            endpoint = match.group(1)
            endpoint_counts[endpoint] += 1
    
    # Find the most frequent endpoint
    most_frequent_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=None)
    return most_frequent_endpoint if most_frequent_endpoint else ('', 0)

# Detect suspicious activity based on failed login attempts
def detect_suspicious_activity(logs):
    failed_logins = defaultdict(int)
    suspicious_ips = {}

    for line in logs:
        # Check for failed login attempts (HTTP status code 401 or "Invalid credentials")
        if '401' in line or 'Invalid credentials' in line:
            # Extract the IP address
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1

    # Flag IPs with failed login attempts exceeding the threshold
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            suspicious_ips[ip] = count
    
    return suspicious_ips

# Save the results to a CSV file
def save_results_to_csv(ip_counts, most_common_endpoint, suspicious_ips, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Write Most Frequently Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_common_endpoint[0], most_common_endpoint[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function to execute all the tasks
def main():
    # Parse the log file
    logs = parse_logs(LOG_FILE)
    
    # Analysis: Requests per IP
    ip_counts = count_requests_per_ip(logs)
    
    # Analysis: Most Frequently Accessed Endpoint
    most_common_endpoint = find_most_frequent_endpoint(logs)
    
    # Analysis: Suspicious Activity
    suspicious_ips = detect_suspicious_activity(logs)
    
    # Display Results in the terminal
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_common_endpoint[0]} (Accessed {most_common_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Count'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    
    # Save Results to CSV
    save_results_to_csv(ip_counts, most_common_endpoint, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

# Run the script
if __name__ == '__main__':
    main()
