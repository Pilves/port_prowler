# Port Prowler

A Python CLI port scanner supporting TCP connect, UDP, and SYN stealth scan types with service detection, OS fingerprinting, and parallel scanning.

## Setup & Installation

```bash
git clone <repo-url>
cd port_prowler
pip install -r requirements.txt
```

## Usage

```
port_prowler.py <ip> [options]

OPTIONS:
    -p      Specify ports (single, multiple comma-separated, or range)
    -tcp    Perform TCP scan
    -udp    Perform UDP scan
    -s      Perform stealth scan
    -f      Save output to file (provide filename after flag)
```

### Examples

```bash
# TCP scan on specific ports
python port_prowler.py 192.168.1.1 -p 80,443,8080 -tcp

# UDP scan on a port range
sudo python port_prowler.py 10.0.0.1 -p 20-25 -udp

# Stealth SYN scan with file output
sudo python port_prowler.py 172.16.0.1 -p 22 -s -f results.txt

# Combined TCP + UDP scan
sudo python port_prowler.py 192.168.1.1 -p 80,443 -tcp -udp
```

## Scan Types Explained

### TCP Connect Scan (`-tcp`)
Performs a full TCP three-way handshake (SYN -> SYN-ACK -> ACK). If the connection completes, the port is **Open**. A RST response means **Closed**. No response means **Filtered**. Does not require root privileges.

### UDP Scan (`-udp`)
Sends a UDP packet to the target port. A UDP response means **Open**. An ICMP port unreachable means **Closed**. No response results in **Open|Filtered** since UDP provides no acknowledgement. Requires root.

### SYN Stealth Scan (`-s`)
Sends a SYN packet without completing the handshake. A SYN-ACK means the port is **Open** (an RST is sent immediately to close). A RST means **Closed**. No response means **Filtered**. Called "stealth" because the connection is never fully established. Requires root.

## Extra Features

- **Service Detection**: Identifies services on open ports using a well-known port table and live banner grabbing
- **OS Detection**: Fingerprints the target OS via ICMP TTL analysis (Linux ~64, Windows ~128, Cisco ~255)
- **Parallel Scanning**: Uses thread pools (up to 100 workers) for fast scanning of port ranges
- **File Output**: Save results to file with `-f`, auto-increments filename if it already exists

## Legal Notice

**Only scan networks you own or have explicit written permission to test.** Unauthorized port scanning may violate laws in your jurisdiction. This tool is intended for educational purposes and authorized security testing only.
