from datetime import datetime
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
    return f"The following actors were found using malicious SQL injections:\nips:{ip_list}\nports:{port_list}\nstatus code:{status_code_list}"

def brute_force(log_data, threshold=5):
    attacker_ips = {}
    for i in log_data:
        if (i["status_code"] in ["401","403"]):
            if not i["ip"] in attacker_ips:
                attacker_ips[i["ip"]] = 1
            else:
                attacker_ips[i["ip"]] += 1
        else:
            continue
        
    for i in attacker_ips.copy().items():
        if i[1] >= threshold:
            continue
        else:
            attacker_ips.pop(i[0])
            
    return f"The following host(s) return brute force activity:\n{attacker_ips}"

def off_hours(log_data, day_start_threshold=4, day_end_threshold=6):
    print_array = []
    for i in log_data:
        temp_date = datetime.strptime(i["date"], "%d/%m/%y")
        temp_time = datetime.strptime(i["time"], "%H:%M:%S")
        datetime_combiner = str(temp_date.date()) + " " + str(temp_time.time())
        if not temp_date.weekday() in range(day_start_threshold, day_end_threshold):
            print_array.append(datetime_combiner)
    return f"Anomalous traffic was found outside of normal hours:\n{print_array}"