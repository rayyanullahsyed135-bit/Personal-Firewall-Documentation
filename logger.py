from datetime import datetime

def log_packet(src_ip, dst_ip, port, protocol, status):
    with open("firewall_log.txt", "a") as f:
        f.write(f"{datetime.now()} | {status} | {src_ip} -> {dst_ip} | {protocol}:{port}\n")
