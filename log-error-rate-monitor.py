import re
import smtplib

log_file ='apache-daily-access.log'
smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_username = 'abc@gmail.com'
smtp_password = 'abc'
recipient = 'abc6@soombo.com'

# define regex pattern to match log entries
log_entry_pattern = r'^(?P<ip_address>[^\s]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[^\s]+) (?P<endpoint>[^\s]+) HTTP/(?P<http_version>[^\s]+)" (?P<status_code>\d{3}) (?P<response_size>\d+) "(?P<referrer>[^\"]*)" "(?P<user_agent>[^\"]*)"'

# define a dictionary of rules and thresholds
rules = {
    'high_traffic': 10000,  # threshold for high traffic (10,000 requests per minute)
    'error_rate': 0.05,  # threshold for error rate (5% of requests resulting in errors)
    'blocked_ips': ['10.0.0.1', '192.168.1.1'],  # list of blocked IPs
    'endpoint_requests': {
        '/login': 10,  # threshold for number of requests for /login endpoint (10 requests per minute)
    },
}

# initialize variables for tracking statistics
requests = 0
errors = 0
ip_counts = {}
endpoint_counts = {}

# list to store high error rate messages
messages = []

# open log file
with open(log_file, 'r') as f:
    # iterate over each line in the file
    for line in f:
        # match the regex pattern against the line
        match = re.match(log_entry_pattern, line)
        if match:
            # extract relevant information from the matched log entry
            ip_address = match.group('ip_address')
            timestamp = match.group('timestamp')
            method = match.group('method')
            endpoint = match.group('endpoint')
            http_version = match.group('http_version')
            status_code = int(match.group('status_code'))
            response_size = int(match.group('response_size'))
            referrer = match.group('referrer')
            user_agent = match.group('user_agent')
            
            # update variables for tracking statistics
            requests += 1
            if status_code >= 400:
                errors += 1
            if ip_address in ip_counts:
                ip_counts[ip_address] += 1
            else:
                ip_counts[ip_address] = 1
            if endpoint in endpoint_counts:
                endpoint_counts[endpoint] += 1
            else:
                endpoint_counts[endpoint] = 1
            
            # check for high traffic
            if requests / 60 >= rules['high_traffic']:
                print(f'High traffic detected at {timestamp}. Requests: {requests}/min')
            
            # check for high error rate
            if errors / requests >= rules['error_rate']:
                message = f'High error rate detected at {timestamp}. Error rate: {errors/requests:.2%}'
                messages.append(message)

# send email if there are any high error rate messages
if messages:
    subject = 'Alert: High Error Rates Detected'
    body = '\n\n'.join(messages)
    message = f'Subject: {subject}\n\n{body}'
    try:
        smtp_connection = smtplib.SMTP(smtp_server, smtp_port)
        smtp_connection.starttls()
        smtp_connection.login(smtp_username, smtp_password)
        smtp_connection.sendmail(smtp_username, recipient, message)
        print('Email sent successfully')
    except Exception as e:
        print(f'Error sending email: {e}')
    finally:
        smtp_connection.quit()