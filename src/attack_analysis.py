from datetime import datetime
from log_parser import parse_log_file

def detect_sql_injection(log_data):
    malicious_sql = ("'", "or", "select", "union", "drop", "delete", "insert", "1=1", "--", "/*", "*/", ";")
    print_array = []
    duplicate_check = []
    for i in log_data:
        for pattern in malicious_sql:
            if pattern in i["request_path"]:
                duplicate_check.append(i["ip"])
                print_array.append(i["ip"] +  " tried the SQL injection '" + i["request_path"] + "' over port " + i["port"])
                
    return "The following actors were found using malicious SQL injections:\n" + "\n".join(f" {actor}" for actor in print_array)

def brute_force(log_data, threshold=5):
    attacker_ips = {}
    print_array = []
    for i in log_data:
        if (i["status_code"] in ["401","403"]):
            if not i["ip"] in attacker_ips:
                attacker_ips[i["ip"]] = 1
            else:
                attacker_ips[i["ip"]] += 1
        else:
            continue

    for i in attacker_ips.copy().items():
        if i[1] <= threshold:
            continue
        else:
            #0 is the ip and 1 is how many times detected
            print_array.append(str(i[0]) + " was detected " + str(i[1]) + " times.")

    return "The following host(s) return brute force activity:\n" + "\n".join(f" {ip}" for ip in print_array)

def off_hours(log_data, day_start_threshold=4, day_end_threshold=6):
    print_array = []
    for i in log_data:
        temp_date = datetime.strptime(i["date"], "%d/%m/%y")
        temp_time = datetime.strptime(i["time"], "%H:%M:%S")
        datetime_combiner = str(temp_date.date()) + " " + str(temp_time.time())
        if not temp_date.weekday() in range(day_start_threshold, day_end_threshold):
            print_array.append(i["ip"] + " tried connecting at: " + datetime_combiner)
    return "Anomalous traffic was found outside of normal hours:\n" + "\n".join(f" {time}" for time in print_array)