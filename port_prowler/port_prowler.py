#!/usr/bin/env python3
import argparse
import socket
import sys

from scanner import check_root, scan_tcp, scan_udp, scan_syn, scan_ports_parallel
from detect import get_service, detect_os
from utils import parse_ports, format_result, save_results


def build_parser():
    parser = argparse.ArgumentParser(
        prog="port_prowler.py",
        usage="port_prowler.py <ip> [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Port Prowler - A port scanning tool",
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
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate IP
    try:
        socket.inet_aton(args.ip)
    except socket.error:
        print(f"Error: Invalid IP address '{args.ip}'")
        sys.exit(1)

    # Check scan type specified
    if not (args.tcp or args.udp or args.s):
        print("Error: No scan type specified. Use -tcp, -udp, or -s. See --help.")
        parser.print_help()
        sys.exit(1)

    # Check -f flag
    if args.outfile == "__missing__":
        print("Error: No filename provided after -f flag.")
        sys.exit(1)

    # Check ports specified
    if not args.ports:
        print("Error: No ports specified. Use -p to specify ports.")
        parser.print_help()
        sys.exit(1)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Check root for UDP/stealth
    if args.udp or args.s:
        check_root()

    # OS detection
    if args.udp or args.s:
        os_info = detect_os(args.ip)
        print(f"Target OS: {os_info}")

    # Determine scan types and labels
    scans = []
    if args.tcp:
        scans.append(("tcp", "TCP", scan_tcp))
    if args.udp:
        scans.append(("udp", "UDP", scan_udp))
    if args.s:
        scans.append(("syn", "Stealth", scan_syn))

    multi_protocol = len(scans) > 1
    all_results = []

    # Print scanning message
    if args.s and len(scans) == 1:
        print(f"\nScanning (stealth) {args.ip}...")
    else:
        print(f"\nScanning {args.ip}...")

    for proto_key, proto_label, scan_fn in scans:
        results = scan_ports_parallel(args.ip, ports, scan_fn)
        for port, state in results:
            service = None
            if state == "Open" and proto_key in ("tcp", "syn"):
                service = get_service(port, state, args.ip)
            protocol = proto_key if multi_protocol else None
            # Map syn to tcp for display in multi-protocol mode
            if protocol == "syn":
                protocol = "tcp(stealth)"
            line = format_result(port, state, service, protocol)
            print(line)
            all_results.append(line)

    # Save to file if requested
    if args.outfile and args.outfile != "__missing__":
        scan_type = ", ".join(label for _, label, _ in scans)
        actual_file = save_results(args.outfile, all_results, target=args.ip, scan_type=scan_type)
        print(f"\nResult written to file: {actual_file}")


if __name__ == "__main__":
    main()
