import os
import ipaddress
import requests
from dotenv import load_dotenv
from log_parser import parse_log_file

load_dotenv()
api_key = os.getenv('ABUSEIPDB_API_KEY')

def count_check(log_entries):
    #iterate once through to add counts for ips in a dictionary
    ip_counts = {}
    for entry in log_entries:
        ip = entry['ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    ip_5_count = []
    ip_10_count = []
    ip_20_count = []
    for ip, count in ip_counts.items():
        if count >= 20:
            ip_20_count.append(ip)
        elif count >= 10:
            ip_10_count.append(ip)
        elif count >= 5:
            ip_5_count.append(ip)

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

def osint_check(log_entries):
    #set will automatically remove all duplicates
    #using generator expression to pull all the ips from log_entries into a unique ips variable
    unique_ips = set(entry['ip'] for entry in log_entries)

    malicious_ips = {}
    for ip in unique_ips:
        if ipaddress.ip_address(ip).is_private:
            continue
        #the := operator allows me to set the variable as the ip_score return value within the if statement, poggers
        elif (ip_score_temp := ip_score(ip)) >= 40:
            malicious_ips[ip] = ip_score_temp
    return f"The following ips return as malicious per OSINT tools:\n{malicious_ips}"

def subnet_check(log_entries):
    subnet_catch = {}
    for entry in log_entries:
        ip = entry['ip']
        #this will catch the index of the rightmost period and we slice from there to get the subnet
        subnet = ip[:(ip.rfind("."))]
        subnet_catch[subnet] = subnet_catch.get(subnet, 0) + 1

    #found a cool way to iterate through the subnets and check which ones pass the threshold called dictionary comprehensions
    subnet_catch = {k: v for k, v in subnet_catch.items() if v > 3}
    return f"The following subnets were seen:\n{subnet_catch}"

log_data = parse_log_file("/Users/churro/Desktop/python/krosis/data/sample_access.log")
print(count_check(log_data))
print("-" * 40)
print(subnet_check(log_data))
print("-" * 40)
print(osint_check(log_data))