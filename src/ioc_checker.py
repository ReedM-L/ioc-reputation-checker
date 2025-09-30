import ipaddress
import requests
import os
import argparse
#!/usr/bin/env python3

"""
IOC Checker Tool
----------------
Takes an IP by user input or a list by file and checks them against threatintelligence sources
"""

def check_ip_abuseipdb(ip: str) -> dict:
    url = 'https://api.abuseipdb.com/api/v2/check'

    query_string = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': os.environ.get("ABUSEIPDB_API_KEY")
    }
    
    response = requests.request(method='GET', url=url, headers=headers, params=query_string)

    response.raise_for_status()

    data = response.json()["data"]

    #return a dict containing just IP and confidence for now
    return {
        "ip": data.get("ipAddress"),
        "confidence": data.get("abuseConfidenceScore"),
    }

def validate_addr(user_ip: str) -> bool:
    #use ipaddress() to check if the user input is a valid address, catch the ValueError if not
    try: 
        ipaddress.ip_address(user_ip)
        print("Valid IP entered, proceeding...")
        return True
    except ValueError:
        print("Invalid IP address entered")
        return False

def main():
    parser = argparse.ArgumentParser(
                        prog="ioc_reputation_checker",
                        description="Takes in either a single IP to check or a lists of IPs from a file")

    #arguments to specify if user is inputting singular input or a file of inputs
    parser.add_argument("--ip", help = "Check a single IP")
    parser.add_argument("--file", help = "Path to input file of IPs to check")
    args = parser.parse_args()
    
    valid_status = False
    print("Confidence Score is a 0 - 100 scale, 0 meaning safe, 100 meaning confidently malicious")
    if args.ip:
        while not valid_status:
            input_ip = input("Enter the IP to check: ")
            valid_status = validate_addr(input_ip)
        data = check_ip_abuseipdb(input_ip)
        print(f"IP: {input_ip} -> Confidence Score (0 - 100): {data['confidence']}")


    if args.file:
        with open(args.file, "r") as f:
            for address in f:
                address = address.strip()
                valid_status = validate_addr(address)
                if (valid_status):
                    #TODO:Add more functionality, want to create an output file maybe of each ip with a corresponding report
                    data = check_ip_abuseipdb(address)
                    print(f"IP: {address} -> Confidence Score (0 - 100): {data['confidence']}")
                else:
                    print("Ill formatted IP: " + address)

if __name__ == "__main__":
    main()
