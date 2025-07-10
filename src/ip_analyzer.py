import os
import ipaddress
import requests
from dotenv import load_dotenv
from log_parser import field_count

load_dotenv()
api_key = os.getenv('ABUSEIPDB_API_KEY')

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

def ip_score(ip):
    headers = {
        'Key' : api_key,
        'Accept' : 'application/json'
    }
    params={
        'ipAddress' : ip,
        'maxAgeInDays' : 90
    }
    response = requests.get(url="https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    return response.json()['data']['abuseConfidenceScore']

def osint_check(log_data):
    malicious_ips = {}
    for ip in log_data["ip"]:
        if ipaddress.ip_address(ip).is_private:
            continue
        #the := operator allows me to set the variable as the ip_score return value within the if statement, poggers
        elif (ip_score_temp := ip_score(ip)) >= 40:
            malicious_ips[ip] = ip_score_temp
            continue
        else:
            continue
    return f"The following ips return as malicious per OSINT tools:\n{malicious_ips}"

def subnet_check(log_data):
    subnet_catch = {}
    for i in log_data["ip"].keys():
        #this will catch the index of the rightmost period and we slice from there to get the subnet
        if not i[:(i.rfind("."))] in subnet_catch:
            subnet_catch[i[:(i.rfind("."))]] = 1
            continue
        else:
            subnet_catch[i[:(i.rfind("."))]] += 1

    #might be cursed but iterating through subnet_catch to remove all below sus threshold
    for i in list(subnet_catch):
        if subnet_catch[i] <= 3:
            subnet_catch.pop(i)
    return f"The following subnets were seen:\n{subnet_catch}"

print(count_check(field_count))
print("-" * 40)
print(subnet_check(field_count))
print("-" * 40)
print(osint_check(field_count))