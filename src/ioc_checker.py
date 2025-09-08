import ipaddress
import requests
#!/usr/bin/env python3

"""
IOC Checker Tool
----------------
Takes an IP by user input or a list by file and checks them against threatintelligence sources
"""
def check_ip_abuseipdb(ip: str, api_key: str):
    


def validate_addr(user_ip):
    #use ipaddress() to check if the user input is a valid address, catch the ValueError if not
    valid_status = false

    try: 
        user_ip = ipaddress.ipaddress(user_ip)
        print("Valid IP entered, proceeding...")
        valid_status = true
        return valid_status
    except:
        print("Invalid IP address entered")
        return valid_status

def main():
    user_ip = input("Enter the IP to check")

    While valid_status != true:
        valid_status = validate_addr(user_ip) 

    

if __name__ == "__main__":
    main()
