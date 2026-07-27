#!/usr/bin/env python3
"""
Host-side ARP table collector.
Run this on the HOST machine to dump ARP data for NetMon.
Output: JSON file with IP→MAC mapping that the container reads.
"""
import json
import platform
import subprocess
import sys
import time
from pathlib import Path


def get_arp_entries() -> list:
    entries = []
    system = platform.system()

    if system == "Linux":
        # Parse /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "00:00:00:00:00:00":
                        entries.append({
                            "ip": parts[0],
                            "mac": parts[3].upper(),
                            "interface": parts[5] if len(parts) > 5 else "",
                        })
        except Exception as e:
            print(f"Warning: /proc/net/arp: {e}", file=sys.stderr)

        # Also try arp -a
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
            for line in result.stdout.split("\n"):
                if "(" in line and ")" in line:
                    ip = line.split("(")[1].split(")")[0]
                    parts = line.split()
                    mac = None
                    for i, p in enumerate(parts):
                        if p == "at" and i + 1 < len(parts):
                            mac = parts[i + 1]
                    if mac and mac not in ("(none)", "ff:ff:ff:ff:ff:ff"):
                        # Check if already have this IP
                        existing = [e for e in entries if e["ip"] == ip]
                        if not existing:
                            entries.append({"ip": ip, "mac": mac.upper(), "interface": ""})
        except Exception:
            pass

    elif system == "Windows":
        # Parse `arp -a` on Windows
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            current_iface = ""
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "Interface:" in line:
                    current_iface = line.split("Interface:")[-1].strip()
                elif line and not line.startswith("---") and not line.startswith("Internet"):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        if mac and mac != "ff-ff-ff-ff-ff-ff":
                            entries.append({
                                "ip": ip,
                                "mac": mac,
                                "interface": current_iface,
                            })
        except Exception as e:
            print(f"Warning: arp -a: {e}", file=sys.stderr)

    elif system == "Darwin":
        # macOS
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split("\n"):
                if "(" in line and ")" in line:
                    ip = line.split("(")[1].split(")")[0]
                    parts = line.split()
                    mac = None
                    for i, p in enumerate(parts):
                        if p == "at" and i + 1 < len(parts):
                            mac = parts[i + 1]
                    if mac and mac not in ("(none)", "ff:ff:ff:ff:ff:ff"):
                        entries.append({"ip": ip, "mac": mac.upper(), "interface": ""})
        except Exception as e:
            print(f"Warning: arp -a: {e}", file=sys.stderr)

    return entries


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("arp_table.json")

    while True:
        entries = get_arp_entries()
        data = {
            "timestamp": time.time(),
            "entries": {e["ip"]: {"mac": e["mac"], "interface": e.get("interface", "")} for e in entries},
        }
        output.write_text(json.dumps(data, indent=2))
        print(f"[{time.strftime('%H:%M:%S')}] {len(entries)} ARP entries -> {output}")
        time.sleep(30)


if __name__ == "__main__":
    main()
