import socket

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8180: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Attempt to grab a service banner from an open TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Try receiving first (some services send banner on connect)
        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            pass
        # Send HTTP probe
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        if banner:
            return banner
    except Exception:
        pass
    return None


def parse_banner(banner: str) -> str | None:
    """Extract service/version info from a banner string."""
    if not banner:
        return None
    # SSH banner
    if banner.startswith("SSH-"):
        parts = banner.split("-", 2)
        if len(parts) >= 3:
            version = parts[2].split(" ")[0]
            return version
    # FTP banner
    if banner.startswith("220"):
        # e.g. "220 (vsFTPd 2.3.4)"
        if "(" in banner and ")" in banner:
            info = banner[banner.index("(") + 1:banner.index(")")]
            return info
        return banner[4:].strip()
    # SMTP
    if banner.startswith("220") and "SMTP" in banner.upper():
        return banner[4:].strip()
    # HTTP Server header
    for line in banner.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


def get_service(port: int, state: str, ip: str) -> str | None:
    """Get service name and version for a port."""
    base = KNOWN_SERVICES.get(port)
    if state != "Open":
        return base

    banner = grab_banner(ip, port)
    version = parse_banner(banner) if banner else None

    if base and version:
        return f"{base} - {version}"
    if version:
        return version
    return base


def detect_os(ip: str) -> str:
    """Detect OS using ICMP TTL analysis."""
    from scapy.all import IP, ICMP, sr1, conf
    conf.verb = 0
    response = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
    if response:
        ttl = response.ttl
        if 60 <= ttl <= 70:
            return "Linux/macOS (TTL ~64)"
        if 120 <= ttl <= 130:
            return "Windows (TTL ~128)"
        if 240 <= ttl <= 255:
            return "Cisco/Network Device (TTL ~255)"
        return f"Unknown (TTL={ttl})"
    return "OS detection failed (no ICMP response)"
