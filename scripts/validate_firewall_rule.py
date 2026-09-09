import os
import sys
import requests
import yaml

NETBOX_URL = os.environ["NETBOX_URL"]
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

print(f"Checking source: {source}")
print(f"Checking destination: {destination}")

source_response = requests.get(
    f"{NETBOX_URL}/api/ipam/ip-addresses/",
    headers=headers,
    params={"address": source},
)

destination_response = requests.get(
    f"{NETBOX_URL}/api/ipam/ip-addresses/",
    headers=headers,
    params={"address": destination},
)

source_data = source_response.json()
destination_data = destination_response.json()

if source_data["count"] == 0:
    print(f"ERROR: Source IP {source} does not exist in NetBox")
    sys.exit(1)

if destination_data["count"] == 0:
    print(f"ERROR: Destination IP {destination} does not exist in NetBox")
    sys.exit(1)

print("Source IP found in NetBox")
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
