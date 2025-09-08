import ipaddress
import requests
import os
import json
#!/usr/bin/env python3

"""
IOC Checker Tool
----------------
Takes an IP by user input or a list by file and checks them against threatintelligence sources
"""

def check_ip_abuseipdb(ip: str):
    url = 'https://api.abuseipdb.com/api/v2/check'

    query_string = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': os.environment.get("ABUSEIPDB_API_KEY")
    }
    
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

def validate_addr(user_ip):
    #use ipaddress() to check if the user input is a valid address, catch the ValueError if not
    valid_status = False

    try: 
        user_ip = ipaddress.ip_address(user_ip)
        print("Valid IP entered, proceeding...")
        valid_status = True
        return valid_status
    except:
        print("Invalid IP address entered")
        return valid_status

def main():
    valid_status = False

    while valid_status != True:
        user_ip = input("Enter the IP to check: ")  
        valid_status = validate_addr(user_ip)
    
    


if __name__ == "__main__":
    main()
