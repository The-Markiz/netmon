#!/usr/bin/env python3
"""
Windows ARP collector — runs on the HOST, not in Docker.
Writes arp_table.json that the NetMon container reads.
Usage: python collect_arp_host.py [output_path]
"""
import json
import subprocess
import sys
import time
from pathlib import Path


def get_windows_arp() -> dict:
    entries = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("---") or line.startswith("Interface") or line.startswith("Internet"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1].replace("-", ":").upper()
                if mac and mac != "FF:FF:FF:FF:FF:FF":
                    entries[ip] = {"mac": mac}
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    return entries


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "arp_table.json"
    print(f"Collecting ARP -> {output}  (Ctrl+C to stop)")
    while True:
        entries = get_windows_arp()
        data = {"timestamp": time.time(), "count": len(entries), "entries": entries}
        output.write_text(json.dumps(data, indent=2))
        print(f"[{time.strftime('%H:%M:%S')}] {len(entries)} ARP entries")
        time.sleep(15)


if __name__ == "__main__":
    main()
