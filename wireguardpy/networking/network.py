import subprocess

import requests
import ipaddress

from typing import Dict


def get_public_ip() -> ipaddress.IPv4Address:
    ip = requests.get('https://api.ipify.org').text
    return ipaddress.IPv4Address(ip)


def get_location() -> Dict:
    FREE_IPSTACK_API_KEY = "IP_STACK_API_KEY"

    public_ip = str(get_public_ip())
    try:
        response = requests.get(f"http://api.ipstack.com/{public_ip}?access_key={FREE_IPSTACK_API_KEY}",
                                timeout=1.0).json()
        location = dict(
            ip=response["ip"],
            country_code=response["country_code"],
            region_code=response["region_code"],
            latitude=response["latitude"],
            longitude=response["longitude"]
        )
    except:
        location = dict(
            ip="",
            country_code="",
            region_code="",
            latitude="",
            longitude="",
        )
    return location


def get_default_route_interface():
    return subprocess.check_output("route | grep '^default' | grep -o '[^ ]*$'", shell=True).decode().strip()
