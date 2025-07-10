import re

#setting up local dictionaries
field_count: dict[str, dict[str, int]] = {
    'ip': {},
    'date': {},
    'time': {},
    'timezone': {},
    'request_type': {},
    'request_path': {},
    'protocol': {},
    'status_code': {},
    'port': {}
}

#line parsing logic
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

#main parsing function call
def parse_log_file(filepath):
    with open(filepath, 'r') as file:
        #loop will take regex group match dictionaries and put them into local dictionaries declared above
        for line in file:
            entry = parse_log_line(line)
            if entry:
                for key, value in entry.items():
                    if value not in field_count[key]:
                        field_count[key][value] = 1
                    else:
                        field_count[key][value] += 1
        return field_count
    return None

#calls
parse_log_file("/Users/churro/Desktop/python/krosis/data/sample_access.log")