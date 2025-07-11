from log_parser import parse_log_file

def detect_sql_injection(log_data):
    malicious_sql = ("'", "or", "select", "union", "drop", "delete", "insert", "1=1", "--", "/*", "*/", ";")
    ip_list = []
    port_list = []
    status_code_list = []
    for i in log_data:
        for pattern in malicious_sql:
            if pattern in i["request_path"]:
                ip_list.append(i["ip"])
                port_list.append(i["port"])
                status_code_list.append(i["status_code"])
    return f"The following actors were found using malicious SQL injections:\n{ip_list}\n{port_list}\n{status_code_list}"

log_data = parse_log_file("/Users/churro/Desktop/python/krosis/data/sample_access.log")
print(detect_sql_injection(log_data))