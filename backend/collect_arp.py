#!/usr/bin/env python3
"""
ARP collector — runs in a container with network_mode: host.
Reads /proc/net/arp and arp -a from the host's network namespace.
Writes JSON to a shared volume.
"""
import json
import platform
import subprocess
import sys
import time
from pathlib import Path


def get_arp_entries() -> dict:
    entries = {}

    # /proc/net/arp (works when running with --network host)
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "00:00:00:00:00:00":
                    entries[parts[0]] = {"mac": parts[3].upper()}
    except Exception:
        pass

    # arp -a fallback
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
                if mac and mac not in ("(none)", "ff:ff:ff:ff:ff:ff") and ip not in entries:
                    entries[ip] = {"mac": mac.upper()}
    except Exception:
        pass

    return entries


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/shared/arp_table.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            entries = get_arp_entries()
            data = {
                "timestamp": time.time(),
                "count": len(entries),
                "entries": entries,
            }
            output.write_text(json.dumps(data, indent=2))
            print(f"[{time.strftime('%H:%M:%S')}] {len(entries)} ARP entries", flush=True)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)
        time.sleep(30)


if __name__ == "__main__":
    main()
