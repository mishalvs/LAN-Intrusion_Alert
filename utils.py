import socket

def get_local_ip():
    """Get the IP address of the current machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unknown"

def is_private_ip(ip):
    """Check if an IP address is private (RFC 1918)."""
    return (
        ip.startswith("10.") or
        ip.startswith("172.") or
        ip.startswith("192.168.")
    )
