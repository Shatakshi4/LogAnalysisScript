import re
from collections import Counter

#parse_log_file
def parse_log_file(file_path):
    ip_addresses = []
    endpoints = []
    failed_logins = Counter()  # Use Counter for failed logins

    # Regular expression to extract the required data from log lines
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] ".* (\/\S+) HTTP.*" (\d{3})')

    # Open the log file and read line by line
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group(1)
                endpoint = match.group(2)
                status_code = match.group(3)
                
                # Add IP, endpoint, and failed login status to respective lists
                ip_addresses.append(ip)
                endpoints.append(endpoint)
                
                if status_code == '401':  # Failed login attempts
                    failed_logins[ip] += 1  # Update the counter for failed logins

    return ip_addresses, endpoints, failed_logins  # Return the counters for all


def display_results(ip_requests, endpoint_access, failed_logins, threshold=10):
    print("\nIP Requests:")
    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = endpoint_access.most_common(1)[0]
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > threshold:
            print(f"{ip:<20} {count}")


#Saving results to csv file
import csv

def save_results_to_csv(ip_requests, endpoint_access, failed_logins, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write IP requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        most_accessed = endpoint_access.most_common(1)[0]
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])



if __name__ == "__main__":
    # File path of the log file
    log_file_path = 'sample.log'

    # Parse the log file
    ip_addresses, endpoints, failed_logins = parse_log_file(log_file_path)

    # Analyze the data (Count requests per IP, identify most accessed endpoint, detect suspicious activity)
    ip_requests = Counter(ip_addresses)
    endpoint_access = Counter(endpoints)

    # Display the results
    display_results(ip_requests, endpoint_access, failed_logins)


