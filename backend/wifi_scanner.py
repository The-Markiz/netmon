"""
WiFi scanner module.
Discovers available WiFi networks and their signal strength.
Works via `netsh wlan` (Windows) or `nmcli`/`iwlist` (Linux).
"""
import logging
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("netmon.wifi")


def scan_wifi_networks() -> List[Dict[str, Any]]:
    """Scan for available WiFi networks and return their properties."""
    system = platform.system()
    if system == "Windows":
        return _scan_wifi_windows()
    elif system == "Linux":
        return _scan_wifi_linux()
    elif system == "Darwin":
        return _scan_wifi_macos()
    return []


def get_wifi_interfaces() -> List[Dict[str, Any]]:
    """Get WiFi interface information."""
    system = platform.system()
    if system == "Windows":
        return _get_wifi_interfaces_windows()
    elif system == "Linux":
        return _get_wifi_interfaces_linux()
    return []


def _scan_wifi_windows() -> List[Dict[str, Any]]:
    """Windows: netsh wlan show networks mode=bssid
    Handles multiple BSSIDs per SSID correctly."""
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=10,
            encoding="cp866", errors="replace",
        )
        if result.returncode != 0:
            return []

        current_ssid = ""
        current = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            # New SSID block (e.g. "SSID 1 : Azatod")
            if line.startswith("SSID") and "BSSID" not in line and ":" in line:
                current_ssid = line.split(":", 1)[1].strip()
                continue

            # New BSSID under same SSID — create new network entry
            if line.startswith("BSSID") and ":" in line:
                if current.get("ssid") and current.get("bssid"):
                    networks.append(current)
                current = {
                    "ssid": current_ssid,
                    "bssid": line.split(":", 1)[1].strip(),
                }
                continue

            if line.startswith("Network type") and ":" in line:
                current["network_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Authentication") and ":" in line:
                current["authentication"] = line.split(":", 1)[1].strip()
            elif line.startswith("Encryption") and ":" in line:
                current["encryption"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signal") and ":" in line:
                try:
                    pct = int(line.split(":", 1)[1].strip().replace("%", ""))
                    current["signal_percent"] = pct
                    current["signal_dbm"] = max(-100, min(0, pct // 2 - 100))
                except ValueError:
                    pass
            elif line.startswith("Radio type") and ":" in line:
                current["radio_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel") and ":" in line:
                current["channel"] = line.split(":", 1)[1].strip()
            elif line.startswith("Band") and ":" in line:
                current["band"] = line.split(":", 1)[1].strip()

        if current.get("ssid") and current.get("bssid"):
            networks.append(current)

        logger.info("WiFi scan (Windows): found %d networks", len(networks))
    except Exception as e:
        logger.debug("WiFi scan Windows failed: %s", e)

    return networks


def _scan_wifi_linux() -> List[Dict[str, Any]]:
    """Linux: try nmcli first, then iwlist."""
    networks = _scan_wifi_nmcli()
    if not networks:
        networks = _scan_wifi_iwlist()
    return networks


def _scan_wifi_nmcli() -> List[Dict[str, Any]]:
    """Linux: nmcli -t -f SSID,SIGNAL,CHAN,SECURITY,BSSID dev wifi list"""
    networks = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,SECURITY,BSSID", "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []

        seen_ssids = set()
        for line in result.stdout.split("\n"):
            parts = line.split(":")
            if len(parts) < 2:
                continue
            ssid = parts[0]
            if not ssid or ssid in seen_ssids:
                continue
            seen_ssids.add(ssid)

            signal = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            channel = parts[2] if len(parts) > 2 else ""
            security = parts[3] if len(parts) > 3 else ""
            bssid = parts[4] if len(parts) > 4 else ""

            networks.append({
                "ssid": ssid,
                "signal_percent": signal,
                "signal_dbm": max(-100, min(0, signal // 2 - 100)) if signal else 0,
                "channel": channel,
                "security": security,
                "bssid": bssid,
                "network_type": "Infrastructure",
            })

        logger.info("WiFi scan (nmcli): found %d networks", len(networks))
    except FileNotFoundError:
        logger.debug("nmcli not found")
    except Exception as e:
        logger.debug("WiFi scan nmcli failed: %s", e)

    return networks


def _scan_wifi_iwlist() -> List[Dict[str, Any]]:
    """Linux: iwlist scanning"""
    networks = []
    try:
        result = subprocess.run(
            ["iwlist", "wlan0", "scanning"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            # Try other interface names
            for iface in ["wlan1", "wlp2s0", "wlp3s0"]:
                result = subprocess.run(
                    ["iwlist", iface, "scanning"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    break

        if result.returncode != 0:
            return []

        current = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if current.get("ssid"):
                    networks.append(current)
                current = {"bssid": line.split("Address:")[-1].strip()}
            elif "ESSID:" in line:
                current["ssid"] = line.split('"')[1] if '"' in line else ""
            elif "Frequency:" in line:
                match = re.search(r"(\d+\.?\d*)\s*GHz", line)
                if match:
                    current["frequency_ghz"] = float(match.group(1))
                    # Calculate channel from frequency
                    freq = current["frequency_ghz"]
                    if 2.4 <= freq <= 2.5:
                        current["channel"] = str(int(round((freq - 2.412) / 0.05) + 1))
                    elif 5.0 <= freq <= 5.9:
                        current["channel"] = str(int(round((freq - 5.0) / 0.05) + 1))
            elif "Signal level=" in line:
                match = re.search(r"Signal level=(-?\d+)", line)
                if match:
                    dbm = int(match.group(1))
                    current["signal_dbm"] = dbm
                    current["signal_percent"] = min(100, max(0, 2 * (dbm + 100)))
            elif "Encryption key:" in line:
                current["encryption"] = "on" if "on" in line else "off"
            elif "IE:" in line and "WPA" in line:
                current["security"] = "WPA"
            elif "IE:" in line and "WPA2" in line:
                current["security"] = "WPA2"
            elif "Channel:" in line:
                match = re.search(r"Channel:(\d+)", line)
                if match:
                    current["channel"] = match.group(1)

        if current.get("ssid"):
            networks.append(current)

        logger.info("WiFi scan (iwlist): found %d networks", len(networks))
    except Exception as e:
        logger.debug("WiFi scan iwlist failed: %s", e)

    return networks


def _scan_wifi_macos() -> List[Dict[str, Any]]:
    """macOS: airport -s"""
    networks = []
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []

        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return []

        # Parse header to find column positions
        header = lines[0]
        cols = {}
        for name in ["SSID", "BSSID", "RSSI", "CHANNEL", "HT", "CC", "SECURITY"]:
            pos = header.find(name)
            if pos >= 0:
                cols[name] = pos

        for line in lines[1:]:
            if not line.strip():
                continue
            ssid = line[cols.get("SSID", 0):cols.get("BSSID", len(line))].strip()
            bssid = line[cols.get("BSSID", 0):cols.get("RSSI", len(line))].strip()
            rssi_str = line[cols.get("RSSI", 0):cols.get("CHANNEL", len(line))].strip()
            channel = line[cols.get("CHANNEL", 0):cols.get("HT", len(line))].strip()
            security = line[cols.get("SECURITY", 0):].strip()

            try:
                rssi = int(rssi_str)
                signal_percent = min(100, max(0, 2 * (rssi + 100)))
            except ValueError:
                rssi = 0
                signal_percent = 0

            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal_dbm": rssi,
                "signal_percent": signal_percent,
                "channel": channel,
                "security": security,
                "network_type": "Infrastructure",
            })

        logger.info("WiFi scan (macOS): found %d networks", len(networks))
    except Exception as e:
        logger.debug("WiFi scan macOS failed: %s", e)

    return networks


def _get_wifi_interfaces_windows() -> List[Dict[str, Any]]:
    """Windows: netsh wlan show interfaces"""
    interfaces = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=5,
            encoding="cp866", errors="replace",
        )
        if result.returncode != 0:
            return []

        current = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("Name") and ":" in line:
                if current.get("name"):
                    interfaces.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Description") and ":" in line:
                current["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("GUID") and ":" in line:
                current["guid"] = line.split(":", 1)[1].strip()
            elif line.startswith("State") and ":" in line:
                current["state"] = line.split(":", 1)[1].strip()
            elif line.startswith("SSID") and "BSSID" not in line and ":" in line:
                current["connected_ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID") and ":" in line:
                current["connected_bssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signal") and ":" in line:
                current["signal_percent"] = line.split(":", 1)[1].strip()
            elif line.startswith("Radio type") and ":" in line:
                current["radio_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel") and ":" in line:
                current["channel"] = line.split(":", 1)[1].strip()
            elif line.startswith("Receive rate") and ":" in line:
                current["receive_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("Transmit rate") and ":" in line:
                current["transmit_rate"] = line.split(":", 1)[1].strip()
            elif line.startswith("Authentication") and ":" in line:
                current["authentication"] = line.split(":", 1)[1].strip()

        if current.get("name"):
            interfaces.append(current)

        logger.info("WiFi interfaces (Windows): found %d", len(interfaces))
    except Exception as e:
        logger.debug("WiFi interfaces Windows failed: %s", e)

    return interfaces


def _get_wifi_interfaces_linux() -> List[Dict[str, Any]]:
    """Linux: iw dev / iwconfig"""
    interfaces = []
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []

        current = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Interface"):
                if current.get("interface"):
                    interfaces.append(current)
                current = {"interface": line.split()[-1]}
            elif "ssid" in line.lower() and current:
                current["ssid"] = line.split(":", 1)[-1].strip().strip('"')
            elif "channel" in line.lower() and current:
                current["channel"] = line.split()[-1]
            elif "tx bitrate" in line.lower() and current:
                current["tx_rate"] = line.split(":", 1)[-1].strip()

        if current.get("interface"):
            interfaces.append(current)

        logger.info("WiFi interfaces (Linux): found %d", len(interfaces))
    except Exception as e:
        logger.debug("WiFi interfaces Linux failed: %s", e)

    return interfaces


def signal_quality(signal_dbm: int) -> str:
    """Convert dBm to human-readable quality."""
    if signal_dbm >= -50:
        return "Отличный"
    elif signal_dbm >= -60:
        return "Хороший"
    elif signal_dbm >= -70:
        return "Средний"
    elif signal_dbm >= -80:
        return "Слабый"
    else:
        return "Очень слабый"


def signal_color(signal_dbm: int) -> str:
    """Return CSS color class based on signal strength."""
    if signal_dbm >= -50:
        return "excellent"
    elif signal_dbm >= -60:
        return "good"
    elif signal_dbm >= -70:
        return "fair"
    elif signal_dbm >= -80:
        return "weak"
    else:
        return "poor"
