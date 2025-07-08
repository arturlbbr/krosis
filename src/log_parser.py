import re

def parse_log_line(line):
    pattern = r'((?:\d+\.){3}\d+)\s-\s-\s\[(\d{2}\/\d{2}\/\d{2})\:(\d{2}\:\d{2}\:\d{2})\s([+-]\d{4})\]\s\"(\w+)\s([^\s]+)\s([A-Z]+\/\d+\.\d+)\"\s(\d+)\s(\d+)$'
    match = re.search(pattern, line)
    
    if match:
        return {
            'ip': match.group(1),
            'date': match.group(2),
            'time': match.group(3),
            'timezone': match.group(4),
            'request_type': match.group(5),
            'request_path': match.group(6),
            'protocol': match.group(7),
            'status_code': match.group(8),
            'port': match.group(9)
        }
    else:
        return None
    
test_lines = ['203.0.113.30 - - [10/07/24:03:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024'
'192.168.1.25 - - [11/07/24:03:05:12 +0100] "GET /about.html HTTP/1.1" 200 512',
'10.0.0.20 - - [12/07/24:03:10:15 +0530] "POST /contact HTTP/1.1" 200 128',
'172.16.0.18 - - [13/07/24:03:15:30 -0700] "GET /products HTTP/1.1" 200 2048',
'198.51.100.22 - - [14/07/24:03:20:45 +0000] "GET /cart HTTP/1.1" 200 256',
'203.0.113.35 - - [15/07/24:03:25:00 +0200] "GET /admin HTTP/1.1" 403 256',
'192.0.2.15 - - [16/07/24:03:30:12 +0000] "GET /favicon.ico HTTP/1.1" 200 4286']

for line in test_lines:
    result = parse_log_line(line)
    print(f"Input: {line}")
    print(f"Output: {result}")
    print("-" * 40)