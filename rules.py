# Define rules here

BLOCKED_IPS = ["192.168.1.10"]
BLOCKED_PORTS = [23, 25]  # Telnet, SMTP
BLOCKED_PROTOCOLS = ["ICMP"]

def is_blocked(src_ip, dst_ip, port, protocol):
    if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
        return True

    if port in BLOCKED_PORTS:
        return True

    if protocol in BLOCKED_PROTOCOLS:
        return True

    return False
