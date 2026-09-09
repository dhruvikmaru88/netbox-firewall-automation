import os
import sys
import requests
import yaml

NETBOX_URL = os.environ["NETBOX_URL"].rstrip("/")
NETBOX_TOKEN = os.environ["NETBOX_TOKEN"]

REQUEST_FILE = sys.argv[1]

with open(REQUEST_FILE, "r") as f:
    rule = yaml.safe_load(f)

headers = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Accept": "application/json",
}

source = rule["source"]
destination = rule["destination"]


def check_ip(ip):
    print(f"Checking IP: {ip}")

    response = requests.get(
        f"{NETBOX_URL}/api/ipam/ip-addresses/",
        headers=headers,
        params={"address": f"{ip}/24"},
    )

    if response.status_code != 200:
        print(f"ERROR: NetBox API returned HTTP {response.status_code}")
        print(response.text)
        sys.exit(1)

    data = response.json()

    if "count" not in data:
        print("ERROR: Unexpected NetBox API response:")
        print(data)
        sys.exit(1)

    return data["count"] > 0


print(f"Checking source: {source}")
print(f"Checking destination: {destination}")

if not check_ip(source):
    print(f"ERROR: Source IP {source} does not exist in NetBox")
    sys.exit(1)

print("Source IP found in NetBox")

if not check_ip(destination):
    print(f"ERROR: Destination IP {destination} does not exist in NetBox")
    sys.exit(1)

print("Destination IP found in NetBox")

print()
print("Firewall request validated successfully")
print("----------------------------------------")
print(f"Request:      {rule['request_id']}")
print(f"Source:       {source}")
print(f"Destination:  {destination}")
print(f"Protocol:     {rule['protocol']}")
print(f"Port:         {rule['destination_port']}")
print(f"Action:       {rule['action']}")
print(f"Description:  {rule['description']}")
