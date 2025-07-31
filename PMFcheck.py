#!/usr/bin/env python3
"""
Analyze pcap file for specified SSIDs and report PMF status
by VoidJarr
"""

import argparse
import os
import sys
from collections import defaultdict

# ANSI escape codes for colored output
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
ENDC = "\033[0m"

# Import Scapy
try:
    from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11EltRSN, Dot11Elt, Dot11, sniff
    from scapy.error import Scapy_Exception
except (ModuleNotFoundError, ImportError) as e:
    print(f"\n{RED}[!] failed to import Scapy: {e}{ENDC}")
    print(f"{YELLOW}[*] install or reinstall Scapy with: {BOLD}pip install --force-reinstall scapy{ENDC}")
    sys.exit(1)


def print_banner() -> None:
    """Display a must-have cool banner"""
    banner = print(f"""
   {CYAN} ___ __  __ ___   _           _   {ENDC}
   {CYAN}| _ \  \/  | __|_| |_  ___ __| |__{ENDC}
   {CYAN}|  _/ |\/| | _/ _| ' \/ -_) _| / /{ENDC}
   {CYAN}|_| |_|  |_|_|\__|_||_\___\__|_\_\\{ENDC}
   {YELLOW}                       by VoidJarr{ENDC}
    """)


def read_ssid_file(ssid_file: str) -> set[str]:
    """Read and validate SSIDs from a file"""
    try:
        with open(ssid_file, "r") as f:
            ssids = {line.strip() for line in f if line.strip()}
            if not ssids:
                print(f"{YELLOW}[!] SSID file is empty or contains no valid SSIDs{ENDC}")
                sys.exit(1)
            return ssids
    except Exception as e:
        print(f"{RED}[!] error reading SSID file: {e}{ENDC}")
        sys.exit(1)


def validate_pcap_file(file_path: str) -> None:
    """Validate that the pcap file exists, is readable, and is not empty"""
    if not os.path.exists(file_path):
        print(f"{RED}[!] pcap file not found: {file_path}{ENDC}")
        sys.exit(1)

    if not os.access(file_path, os.R_OK):
        print(f"{RED}[!] insufficient permissions to read pcap file: {file_path}{ENDC}")
        sys.exit(1)

    if os.path.getsize(file_path) == 0:
        print(f"{RED}[!] pcap file is empty: {file_path}{ENDC}")
        sys.exit(1)


def main(pcap_file: str, ssid_file: str | None) -> None:
    # Validate the pcap file
    validate_pcap_file(pcap_file)

    # Load target SSIDs if provided
    target_ssids = read_ssid_file(ssid_file) if ssid_file else None

    # Dictionary to store AP info: BSSID -> (SSID, MFPC, MFPR)
    ap_info = {}

    def process_packet(packet) -> None:
        """Process each packet to extract SSID and PMF information"""
        # Skip packets without Dot11Elt layer
        if not packet.haslayer(Dot11Elt):
            return

        # Attempt to decode SSID
        try:
            ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, AttributeError, ValueError):
            return

        # Check if SSID is non-empty but consists entirely of null bytes, indicating a hidden SSID, and just show its length
        if ssid and not ssid.strip('\x00'):
            ssid = f"<length: {len(ssid)}>"

        # Skip if SSID is invalid or not targeted
        if not ssid or (target_ssids and ssid not in target_ssids):
            return

        # Skip packets without Dot11 layer
        if not packet.haslayer(Dot11):
            return

        # Extract BSSID
        bssid = packet[Dot11].addr3

        # Skip if BSSID invalid or already processed
        if not bssid or bssid in ap_info:
            return

        # Extract RSN information for PMF
        rsn = packet.getlayer(Dot11EltRSN)
        mfpc = rsn.mfp_capable if rsn else 0
        mfpr = rsn.mfp_required if rsn else 0

        # Store AP details
        ap_info[bssid] = (ssid, mfpc, mfpr)

    # --- Packet Processing Section ---
    print(f"{CYAN}[*] analyzing pcap file: {os.path.basename(pcap_file)}{ENDC}")

    # Display SSID check information
    if target_ssids:
        count = len(target_ssids)
        ssid_text = "SSID" if count == 1 else "SSIDs"
        print(f"{CYAN}[*] checking {count} target {ssid_text}{ENDC}")
    else:
        print(f"{CYAN}[*] checking all available SSIDs{ENDC}")

    # Process the pcap file
    try:
        sniff(
            offline=pcap_file,
            filter="wlan type mgt subtype beacon or wlan type mgt subtype probe-resp",
            prn=process_packet,
            store=0,
            quiet=True,
        )
    except Scapy_Exception as e:
        print(f"\n{RED}[!] pcap processing error: {e}{ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[!] unexpected error during pcap processing: {e}{ENDC}")
        sys.exit(1)

    # Display found AP count
    ap_count = len(ap_info)
    ap_text = "access point" if ap_count == 1 else "access points"
    print(f"{CYAN}[*] found {ap_count} {ap_text}{ENDC}")

    # Exit if no APs found
    if not ap_info:
        print(f"{YELLOW}[!] no access points found in capture{ENDC}")
        sys.exit(0)

    # --- Results Compilation Section ---
    # Group results by SSID
    ssid_group = defaultdict(list)
    for bssid, (ssid, mfpc, mfpr) in ap_info.items():
        # Determine PMF status with color
        if mfpr:
            status = f"{GREEN}required{ENDC}"
        elif mfpc:
            status = f"{YELLOW}enabled (optional){ENDC}"
        else:
            status = f"{RED}not supported{ENDC}"

        # Add status to group
        ssid_group[ssid].append(f"{bssid}: {status}")

    # --- Results Presentation Section ---
    # Print results header
    print(f"\n{BOLD}========= PMF Analysis Results ========={ENDC}\n")

    # Determine SSIDs to report
    report_ssids = sorted(target_ssids) if target_ssids else sorted(ssid_group.keys())

    # Check for reportable SSIDs
    if not report_ssids:
        print(f"{YELLOW}[!] no SSID found for reporting{ENDC}")
        return

    # Output results for each SSID
    for ssid in report_ssids:
        print(f"{BOLD}{ssid}{ENDC}")

        if ssid in ssid_group:
            for status in ssid_group[ssid]:
                print(f"   {status}")
        else:
            print(f"  {RED}not found in capture{ENDC}")

        print()  # Blank line separator


if __name__ == "__main__":
    # Display the banner
    print_banner()

    # Configure argument parser
    parser = argparse.ArgumentParser(
        description="analyze pcap file for specified SSIDs and report PMF status",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("pcap_file", help="path to pcap file for analysis")
    parser.add_argument(
        "ssid_file",
        nargs="?",
        default=None,
        help="optional file containing SSIDs to check (one per line)",
    )

    # Parse command-line arguments
    args = parser.parse_args()
    # Run the main function
    main(args.pcap_file, args.ssid_file)
