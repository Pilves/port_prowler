# Port Prowler — Technical Specification

## Overview

A Python CLI port scanner covering all required scan types, extra features, and every reviewer test case. No external dependencies beyond `scapy`. Pure stdlib for TCP; scapy for UDP, SYN stealth, and OS detection.

---

## File Structure

```
port_prowler/
├── port_prowler.py     # CLI entrypoint — argparse, orchestration, output
├── scanner.py          # Scan logic: TCP, UDP, stealth (SYN)
├── detect.py           # Service banner grabbing + OS fingerprinting
├── utils.py            # Port parsing, output formatting, file saving
├── requirements.txt    # scapy>=2.5
└── README.md
```

---

## Module Contracts

### `utils.py`

#### `parse_ports(port_string: str) -> list[int]`
Accepts any of the three formats and returns a sorted, deduplicated list of integers.

- `"80"` → `[80]`
- `"80,443,8080"` → `[80, 443, 8080]`
- `"20-25"` → `[20, 21, 22, 23, 24, 25]`
- Mixed: `"22,80,100-103"` → `[22, 80, 100, 101, 102, 103]`

Validation rules:
- Each port must be an integer 1–65535.
- Range must have `start <= end`.
- Any violation raises `ValueError` with a descriptive message.

#### `format_result(port: int, state: str, service: str | None = None) -> str`
Returns a single line string:
```
Port 80: Open (HTTP - Apache httpd 2.2.8)
Port 443: Closed
Port 8080: Filtered
```
`service` is only appended when provided and non-empty.

#### `save_results(filename: str, lines: list[str]) -> str`
- If `filename` already exists, auto-increment: `scan_results.txt` → `scan_results1.txt` → `scan_results2.txt` etc.
- Writes header with timestamp and target IP, then all result lines.
- Returns the actual filename used (for display confirmation).

---

### `scanner.py`

All scan functions share this signature:
```python
def scan_tcp(ip: str, port: int, timeout: float = 1.0) -> str
def scan_udp(ip: str, port: int, timeout: float = 2.0) -> str
def scan_syn(ip: str, port: int, timeout: float = 2.0) -> str
```
Return value is always one of: `"Open"`, `"Closed"`, `"Filtered"`, `"Open|Filtered"`

#### TCP Connect Scan (`scan_tcp`)
```
socket.connect_ex((ip, port))
  → 0          : "Open"
  → ECONNREFUSED: "Closed"
  → timeout    : "Filtered"
  → other      : "Filtered"
```
Uses `socket.setblocking(False)` + `select` pattern for clean timeout handling.
No root required.

#### UDP Scan (`scan_udp`)
Uses scapy. Root required.
```
Send: IP(dst=ip)/UDP(dport=port)
  → UDP response           : "Open"
  → ICMP type 3, code 3    : "Closed"   (port unreachable)
  → ICMP other             : "Filtered"
  → No response (timeout)  : "Open|Filtered"
```
The `Open|Filtered` ambiguity is intentional and correct — UDP provides no acknowledgement. This will match Nmap's behavior exactly.

#### SYN Stealth Scan (`scan_syn`)
Uses scapy. Root required.
```
Send: IP(dst=ip)/TCP(dport=port, flags="S")
  → SYN-ACK (flags=0x12): "Open"
    (immediately send RST to avoid completing handshake)
  → RST-ACK (flags=0x14) : "Closed"
  → No response (timeout): "Filtered"
  → ICMP unreachable     : "Filtered"
```
The RST is sent to avoid leaving half-open connections on the target — this is what makes it "stealth". Do NOT use `sr1(verbose=0)` without suppressing scapy's default output.

#### `check_root() -> None`
Called at startup when `-udp` or `-s` is passed:
```python
import os
if os.geteuid() != 0:
    sys.exit("Error: UDP and stealth scans require root. Run with sudo.")
```

#### Parallel Scanning
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    return sorted(results)   # sort by port number for consistent output
```
Applies to all scan types. Closed/filtered ports during parallel scan are caught individually — one bad port never kills the run.

---

### `detect.py`

#### `get_service(port: int, state: str, ip: str) -> str | None`
Two-step approach:

**Step 1 — Well-known port table** (always runs, fast):
```python
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    # ... extend as needed
}
```

**Step 2 — Banner grab** (only for Open TCP ports, 2s timeout):
```python
sock.connect((ip, port))
sock.settimeout(2)
sock.send(b"HEAD / HTTP/1.0\r\n\r\n")   # generic probe
banner = sock.recv(1024).decode(errors="ignore").strip()
```
Parse banner for service/version strings (e.g., `"SSH-2.0-OpenSSH_4.7p1"`, `"220 (vsFTPd 2.3.4)"`).
Return combined: `"SSH (OpenSSH 4.7p1)"`.

If banner grab fails (connection refused, timeout, decode error) — silently fall back to table result.

#### `detect_os(ip: str) -> str`
Uses scapy ICMP ping + TTL inspection:
```python
response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
if response:
    ttl = response.ttl
    if 60 <= ttl <= 70:   return "Linux/macOS (TTL ~64)"
    if 120 <= ttl <= 130: return "Windows (TTL ~128)"
    if 240 <= ttl <= 255: return "Cisco/Network Device (TTL ~255)"
    return f"Unknown (TTL={ttl})"
return "OS detection failed (no ICMP response)"
```
TTL ranges instead of exact match — hops reduce the value.
This runs once before the port scan loop when any scan type is active.

---

### `port_prowler.py`

#### Argument Parsing

```python
parser = argparse.ArgumentParser(
    prog="port_prowler.py",
    usage="port_prowler.py <ip> [options]",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description="Port Prowler 🕷️ — A port scanning tool",
    epilog="""
OPTIONS:
    -p      Specify ports (single, multiple comma-separated, or range)
    -tcp    Perform TCP scan
    -udp    Perform UDP scan
    -s      Perform stealth scan
    -f      Save output to file (provide filename after flag)

EXAMPLES:
    port_prowler.py 192.168.1.1 -p 80,443,8080 -tcp
    port_prowler.py 10.0.0.1 -p 20-25 -udp
    port_prowler.py 172.16.0.1 -p 22 -s -f results.txt
"""
)

parser.add_argument("ip", help="Target IP address")
parser.add_argument("-p", dest="ports", help="Port(s) to scan")
parser.add_argument("-tcp", action="store_true", help="TCP connect scan")
parser.add_argument("-udp", action="store_true", help="UDP scan")
parser.add_argument("-s", action="store_true", help="Stealth SYN scan")
parser.add_argument("-f", dest="outfile", nargs="?", const="__missing__",
                    help="Output file")
```

> **Note on `-f` flag:** Using `nargs="?"` with `const="__missing__"` lets you detect when `-f` is passed without a filename. Check for `"__missing__"` and print an error rather than crashing.

#### Edge Case Handling (all reviewer test cases covered)

| Invocation | Expected Behaviour |
|---|---|
| `port_prowler.py <ip>` | Error: "No scan type specified. Use -tcp, -udp, or -s. See --help." |
| `port_prowler.py <ip> -p` | argparse raises error: "argument -p: expected one argument" |
| `port_prowler.py <ip> -p 80` | Error: "No scan type specified. Use -tcp, -udp, or -s." |
| `port_prowler.py <ip> -p 80 -tcp -udp` | Run both scans, display results for each protocol per port |
| `port_prowler.py <ip> -p 80 -tcp -f` | Error: "No filename provided after -f flag." |
| `port_prowler.py <ip> -p 80 -tcp -f results.txt` | Scan, print to terminal, AND write to file |

For "no scan type" error, print the help text in full, then exit 1. This satisfies "displaying usage information on invalid arguments."

#### Multi-Protocol Behaviour

When both `-tcp` and `-udp` are passed:
- Run TCP scan for all ports, collect results
- Run UDP scan for all ports, collect results
- Display merged output grouped by port:
```
Port 80/tcp: Open (HTTP - Apache httpd 2.2.8)
Port 80/udp: Open|Filtered
```

#### Main Flow

```
1. parse_args()
2. validate ip (socket.inet_aton — catches bad IPs early)
3. parse_ports() — exit with clean error if invalid
4. check edge cases (no scan type, missing filename, etc.)
5. check_root() if udp or stealth
6. detect_os() — print "Target OS: Linux/macOS (TTL ~64)"
7. print "Scanning [stealth] <ip>..."
8. for each scan type requested:
     a. scan_ports_parallel() with appropriate scan_fn
     b. for each (port, state):
          - if Open + TCP: get_service(port, state, ip)
          - format_result(port, state, service)
          - print to terminal immediately
          - append to results list
9. if -f: save_results(filename, results) and print confirmation
```

Print results as they come in (not at the end) — better UX for large port ranges.

---

## Output Format

Must exactly match the spec examples. Reference strings:

```
Scanning 192.168.1.1...
Port 80: Open (HTTP - Apache httpd 2.2.8)
Port 443: Closed
Port 8080: Filtered

Scanning (stealth) 172.16.0.1...
Port 22: Open (SSH - OpenSSH 4.7p1)
Result written to file: scan_results.txt
```

For multi-protocol:
```
Scanning 192.168.1.1...
Port 80/tcp: Open (HTTP - Apache httpd 2.2.8)
Port 80/udp: Open|Filtered
```

File output includes a header:
```
=== Port Prowler Scan Results ===
Target: 192.168.1.1
Date:   2024-01-15 14:32:01
Scan:   TCP
=================================
Port 80: Open (HTTP - Apache httpd 2.2.8)
...
```

---

## UFW / Filtered State Accuracy

This is specifically tested in review. When UFW is enabled on Metasploitable:
- **TCP scan:** blocked ports appear as `Filtered` (connection times out). This matches Nmap's `-sT`.
- **SYN scan:** UFW drops SYN packets silently → `Filtered`. Matches Nmap's `-sS`.

Your timeout handling must be tight enough to complete in reasonable time:
- TCP timeout: **1.0s** per port
- SYN timeout: **2.0s** per port (raw packets are slower)
- UDP timeout: **2.0s** per port

With 100-thread parallelism, scanning 3 ports with any method should complete in under 3 seconds.

---

## Nmap Comparison Accuracy

The reviewer will run:
```bash
nmap -p 80,443,8080 -v <ip>           # TCP
nmap -p 80,443,8080 -v -sU <ip>       # UDP
nmap -p 80,443,8080 -v -sS <ip>       # SYN (with UFW)
```

Your results must match state-for-state. Key alignment points:

| Nmap state | Your state |
|---|---|
| `open` | `Open` |
| `closed` | `Closed` |
| `filtered` | `Filtered` |
| `open\|filtered` | `Open\|Filtered` |

Nmap uses the same logic you're implementing — the states will match if your timeout and response parsing is correct.

---

## `requirements.txt`

```
scapy>=2.5.0
```

---

## `README.md` — Required Sections

1. **Project Overview** — what it does, what protocols, what techniques
2. **Setup & Installation**
   ```bash
   git clone ...
   pip install -r requirements.txt
   # or: pip install scapy
   ```
3. **Usage Guide** — copy the help output, then one example per scan type
4. **Scan Types Explained** — brief description of TCP, UDP, SYN stealth
5. **Extra Features** — service detection, OS detection, parallel scanning
6. **Legal Notice** — only scan networks you own or have explicit permission to test

---

## Implementation Order

Build in this order — each step is independently testable:

1. **`utils.py`** — `parse_ports` + `format_result`. Test offline with `python -c "from utils import parse_ports; print(parse_ports('20-25'))"`.
2. **`scanner.py` TCP only** — no root, test against localhost or any known IP.
3. **`port_prowler.py` skeleton** — wire up argparse + all edge case handling. Test all error paths without any scanning.
4. **`scanner.py` UDP + SYN** — requires root + scapy. Test against Metasploitable.
5. **`detect.py`** — service table first (offline), then banner grab, then OS detect.
6. **`utils.py` `save_results`** — file output + auto-increment logic.
7. **Threading** — it's a drop-in swap; add last and verify output order is consistent.
8. **Full Metasploitable run** — do the exact nmap comparison tests yourself before review.

---

## Metasploitable 2 — Known Open Ports

Use these to verify your scanner before review:

| Port | Service | Expected State |
|---|---|---|
| 21 | FTP (vsFTPd 2.3.4) | Open |
| 22 | SSH (OpenSSH 4.7p1) | Open |
| 23 | Telnet | Open |
| 25 | SMTP (Postfix) | Open |
| 80 | HTTP (Apache 2.2.8) | Open |
| 3306 | MySQL 5.0.51a | Open |
| 5432 | PostgreSQL 8.3 | Open |
| 8180 | Apache Tomcat | Open |

Default Metasploitable IP in host-only networking: typically `192.168.56.101` or `192.168.1.x` — confirm with `ifconfig` inside the VM.

Enable UFW for firewall tests: `sudo ufw enable` inside the VM. Disable after: `sudo ufw disable`.

---

## Concepts to Know for Review

**What is a port?** A 16-bit number (1–65535) that identifies a specific process/service on a host. IP routes traffic to a machine; port routes it to the right service.

**TCP handshake:** SYN → SYN-ACK → ACK. Three-way. Connection-oriented, reliable. TCP scan exploits this: a completed handshake = Open, RST = Closed, silence = Filtered.

**UDP:** Connectionless, no handshake. You fire a packet and either get a response or you don't. An ICMP "port unreachable" means Closed; silence means the port is Open or the packet was dropped (Filtered) — you can't tell which, hence `Open|Filtered`.

**SYN stealth:** Send SYN, receive SYN-ACK (port is open), immediately send RST instead of completing the handshake. Never logged by many older services because the connection was never "established." Requires raw socket access (root).

**Why topology matters:** You can't secure what you don't know exists. Port scanning reveals attack surface — unexpected open ports mean unexpected services, unexpected services mean unexpected vulnerabilities.
