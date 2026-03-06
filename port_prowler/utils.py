import os
from datetime import datetime


def parse_ports(port_string: str) -> list[int]:
    """Parse port specification into sorted, deduplicated list of ints."""
    ports = set()
    parts = port_string.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2:
                raise ValueError(f"Invalid range: {part}")
            start, end = int(bounds[0]), int(bounds[1])
            if start > end:
                raise ValueError(f"Invalid range: start ({start}) > end ({end})")
            if start < 1 or end > 65535:
                raise ValueError(f"Ports must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of range (1-65535)")
            ports.add(p)
    return sorted(ports)


def format_result(port: int, state: str, service: str | None = None, protocol: str | None = None) -> str:
    """Format a single scan result line."""
    port_str = f"{port}/{protocol}" if protocol else str(port)
    if service:
        return f"Port {port_str}: {state} ({service})"
    return f"Port {port_str}: {state}"


def save_results(filename: str, lines: list[str], target: str = "", scan_type: str = "") -> str:
    """Save results to file with auto-increment if file exists."""
    actual = filename
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(actual):
        actual = f"{base}{counter}{ext}"
        counter += 1

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(actual, "w") as f:
        f.write("=== Port Prowler Scan Results ===\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date:   {now}\n")
        f.write(f"Scan:   {scan_type}\n")
        f.write("=================================\n")
        for line in lines:
            f.write(line + "\n")
    return actual
