import threading
from scapy.all import ARP, Ether, srp
import socket
import re
import requests

def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
    except:
        return "Unknown"
    return "Unknown"

def is_valid_mac(mac):
    return re.match("[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac.lower())

def scan_devices():
    devices = []

    # Detect local IP range automatically
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_range = ".".join(local_ip.split(".")[:3]) + ".1/24"
    except:
        ip_range = "192.168.1.1/24"

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        if is_valid_mac(mac):
            vendor = get_vendor(mac)
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor
            })

    return devices
