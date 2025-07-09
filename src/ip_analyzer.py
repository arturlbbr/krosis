from log_parser import field_count

def count_check(log_data):
    ip_5_count = []
    ip_10_count = []
    ip_20_count = []
    for i in log_data["ip"]:
        if log_data["ip"][i] >= 20:
            ip_20_count.append(i)
        elif log_data["ip"][i] >= 10:
            ip_10_count.append(i)
        elif log_data["ip"][i] >= 5:
            ip_5_count.append(i)
        else:
            continue
    if ip_5_count or ip_10_count or ip_20_count:
        return f"The following ips were seen in a high volume:\n5+ times: {ip_5_count}\n10+ times: {ip_10_count}\n20+ times {ip_20_count}"
    return "No high ip count seen"

def osint_check():
    pass

def subnet_check():
    pass

print(count_check(field_count))