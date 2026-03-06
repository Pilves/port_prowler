import socket
import select
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_root():
    if os.geteuid() != 0:
        sys.exit("Error: UDP and stealth scans require root. Run with sudo.")


def scan_tcp(ip: str, port: int, timeout: float = 1.0) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        err = sock.connect_ex((ip, port))
        if err == 0:
            return "Open"
        # In-progress connection
        _, wlist, _ = select.select([], [sock], [], timeout)
        if wlist:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                return "Open"
            elif err == 111:  # ECONNREFUSED
                return "Closed"
            else:
                return "Filtered"
        else:
            return "Filtered"
    except socket.error:
        return "Filtered"
    finally:
        sock.close()


def scan_udp(ip: str, port: int, timeout: float = 2.0) -> str:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    conf.verb = 0
    pkt = IP(dst=ip) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "Open|Filtered"
    if resp.haslayer(UDP):
        return "Open"
    if resp.haslayer(ICMP):
        icmp = resp.getlayer(ICMP)
        if icmp.type == 3 and icmp.code == 3:
            return "Closed"
        return "Filtered"
    return "Open|Filtered"


def scan_syn(ip: str, port: int, timeout: float = 2.0) -> str:
    from scapy.all import IP, TCP, ICMP, sr1, send, conf
    conf.verb = 0
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        return "Filtered"
    if resp.haslayer(TCP):
        tcp_flags = resp.getlayer(TCP).flags
        if tcp_flags == 0x12:  # SYN-ACK
            # Send RST to tear down half-open connection
            rst = IP(dst=ip) / TCP(dport=port, flags="R")
            send(rst, verbose=0)
            return "Open"
        elif tcp_flags & 0x04:  # RST
            return "Closed"
    if resp.haslayer(ICMP):
        return "Filtered"
    return "Filtered"


def scan_ports_parallel(ip, ports, scan_fn, max_workers=100) -> list[tuple[int, str]]:
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futures = {ex.submit(scan_fn, ip, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                state = future.result()
            except Exception:
                state = "Filtered"
            results.append((port, state))
    return sorted(results)
