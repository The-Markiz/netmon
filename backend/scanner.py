import asyncio
import ipaddress
import json
import logging
import os
import platform
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

import psutil

from database import (
    create_scan_record,
    finish_scan_record,
    get_all_devices,
    get_device_by_ip,
    get_latest_snapshot,
    mark_device_offline,
    save_device_snapshot,
    set_ports,
    update_device_hardware,
    upsert_device,
)
from data.oui import lookup_vendor
from classifier import classify_device, get_classification_details

logger = logging.getLogger("netmon.scanner")

# ── Config ──

SCAN_INTERVAL = int(os.getenv("NETMON_SCAN_INTERVAL", "30"))
SCAN_TYPE = os.getenv("NETMON_SCAN_TYPE", "auto")  # auto | nmap | scapy


# ── Status tracking ──

@dataclass
class ScanStatus:
    running: bool = False
    scan_type: str = ""
    started_at: str = ""
    progress: int = 0
    total: int = 0
    devices_found: int = 0
    new_devices: int = 0
    last_scan_at: str = ""
    error: str = ""


class Scanner:
    def __init__(self):
        self.status = ScanStatus()
        self._task: Optional[asyncio.Task] = None
        self._listeners: List[Callable] = []
        self._nmap_available: Optional[bool] = None
        self._gateway_ip: Optional[str] = None
        self._subnet: Optional[str] = None
        self.scan_interval: int = SCAN_INTERVAL
        self.subnet: Optional[str] = None
        self._detected_subnets: List[Dict[str, str]] = []

    # ── Listeners ──

    def add_listener(self, callback: Callable):
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable):
        self._listeners = [l for l in self._listeners if l is not callback]

    async def _emit(self, event_type: str, data: Dict[str, Any]):
        for listener in self._listeners:
            try:
                await listener(event_type, data)
            except Exception:
                logger.exception("Listener error")

    # ── Subnet detection ──

    def _detect_all_subnets(self) -> List[Dict[str, str]]:
        """Detect all private network subnets on this host.
        Returns list of dicts: [{subnet, gateway, interface, score}, ...]
        """
        # Env var overrides everything
        env_subnet = os.getenv("NETMON_SUBNET")
        if env_subnet:
            gw = env_subnet.split("/")[0].rsplit(".", 1)[0] + ".1"
            self._detected_subnets = [{"subnet": env_subnet, "gateway": gw, "interface": "env", "score": 100}]
            self._subnet = env_subnet
            self._gateway_ip = gw
            logger.info("Using configured subnet: %s", env_subnet)
            return self._detected_subnets

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            # Find default gateway
            gateway_ip = None
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.split("\n"):
                        if "Default Gateway" in line and ":" in line:
                            gw = line.split(":")[-1].strip()
                            if gw and gw != "None" and "." in gw:
                                gateway_ip = gw
                                break
                else:
                    result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.split("\n"):
                        if "default via" in line:
                            gateway_ip = line.split("via")[1].strip().split()[0]
                            break
            except Exception:
                pass

            # Collect all private subnets
            candidates = []
            seen_networks = set()
            for iface_name, iface_addrs in addrs.items():
                iface_stats = stats.get(iface_name)
                if iface_stats and not iface_stats.isup:
                    continue
                for addr in iface_addrs:
                    if addr.family != socket.AF_INET or not addr.address:
                        continue
                    ip = addr.address
                    if ip.startswith("127."):
                        continue
                    netmask = addr.netmask or "255.255.255.0"
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    except ValueError:
                        continue
                    if not network.is_private:
                        continue
                    # Skip link-local (169.254.x.x) and very large subnets
                    if str(network.network_address).startswith("169.254"):
                        continue
                    if network.prefixlen < 16:
                        continue
                    net_str = str(network)
                    if net_str in seen_networks:
                        continue
                    seen_networks.add(net_str)

                    score = 0
                    gw_ip = gateway_ip or str(network.network_address + 1)
                    if gateway_ip:
                        try:
                            gw_network = ipaddress.IPv4Network(f"{gateway_ip}/{netmask}", strict=False)
                            if network == gw_network:
                                score = 100
                        except ValueError:
                            pass
                    if network.prefixlen == 24:
                        score += 10
                    if not str(network.network_address).startswith("127."):
                        score += 5

                    candidates.append({
                        "subnet": net_str,
                        "gateway": gw_ip,
                        "interface": iface_name,
                        "score": score,
                    })

            if candidates:
                candidates.sort(key=lambda x: x["score"], reverse=True)
                self._detected_subnets = candidates
                best = candidates[0]
                self._subnet = best["subnet"]
                self._gateway_ip = best["gateway"]
                logger.info("Detected %d subnets: %s", len(candidates),
                           ", ".join(f"{c['subnet']} ({c['interface']})" for c in candidates))
                return candidates

        except Exception as e:
            logger.warning("Failed to auto-detect subnets: %s", e)

        fallback = "192.168.1.0/24"
        self._detected_subnets = [{"subnet": fallback, "gateway": "192.168.1.1", "interface": "fallback", "score": 0}]
        self._subnet = fallback
        self._gateway_ip = "192.168.1.1"
        logger.info("Using fallback subnet: %s", fallback)
        return self._detected_subnets

    def _detect_subnet(self) -> str:
        """Backward-compatible: returns the best subnet string."""
        if self._detected_subnets:
            return self._detected_subnets[0]["subnet"]
        self._detect_all_subnets()
        return self._subnet or "192.168.1.0/24"

    # ── Nmap detection ──

    def _check_nmap(self) -> bool:
        if self._nmap_available is not None:
            return self._nmap_available
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            self._nmap_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._nmap_available = False
        logger.info("Nmap available: %s", self._nmap_available)
        return self._nmap_available

    # ── Host discovery ──

    async def _discover_hosts(self, subnet: str) -> List[Dict[str, str]]:
        scan_type = SCAN_TYPE
        if scan_type == "nmap" or (scan_type == "auto" and self._check_nmap()):
            self.status.scan_type = "nmap"
            return await self._discover_hosts_nmap(subnet)
        else:
            self.status.scan_type = "scapy"
            return await self._discover_hosts_scapy(subnet)

    async def _discover_hosts_nmap(self, subnet: str) -> List[Dict[str, str]]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._nmap_scan_hosts, subnet)
        except Exception as e:
            logger.error("Nmap host discovery failed: %s", e)
            return []

    def _nmap_scan_hosts(self, subnet: str) -> List[Dict[str, str]]:
        import nmap
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=subnet, arguments="-sn -n")
        except nmap.PortScannerError as e:
            logger.warning("Nmap scan error: %s", e)
            return []

        hosts = []
        for host in nm.all_hosts():
            mac = nm[host].get("addresses", {}).get("mac")
            hostname = nm[host].get("hostname", "")
            vendor = None
            if "vendor" in nm[host] and nm[host]["vendor"]:
                vendor = list(nm[host]["vendor"].values())[0] if nm[host]["vendor"] else None
            hosts.append({"ip": host, "mac": mac, "hostname": hostname, "vendor": vendor})

        # Enrich from ARP table
        hosts = self._enrich_from_arp(hosts)
        return hosts

    async def _discover_hosts_scapy(self, subnet: str) -> List[Dict[str, str]]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scapy_arp_scan, subnet)
        except Exception as e:
            logger.error("Scapy host discovery failed: %s", e)
            return []

    def _scapy_arp_scan(self, subnet: str) -> List[Dict[str, str]]:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(packet, timeout=2, verbose=0)
        except Exception as e:
            logger.warning("Scapy ARP scan error: %s", e)
            return []
        hosts = []
        for _, rcv in answered:
            mac = rcv.hwsrc
            hosts.append({
                "ip": rcv.psrc,
                "mac": mac,
                "hostname": "",
                "vendor": lookup_vendor(mac),
            })
        return hosts

    # ── ARP table enrichment ──

    def _enrich_from_arp(self, hosts: List[Dict[str, str]]) -> List[Dict[str, str]]:
        arp_table = self._get_arp_table()
        for host in hosts:
            ip = host["ip"]
            if not host.get("mac") and ip in arp_table:
                host["mac"] = arp_table[ip]["mac"]
                if not host.get("hostname") and arp_table[ip].get("hostname"):
                    host["hostname"] = arp_table[ip]["hostname"]
            if host.get("mac") and not host.get("vendor"):
                host["vendor"] = lookup_vendor(host["mac"])
        return hosts

    def _get_arp_table(self) -> Dict[str, Dict[str, str]]:
        arp = {}

        # 1. Try ARP file from host collector (shared volume, Docker mode)
        arp_file = os.getenv("ARP_FILE", "")
        if arp_file:
            try:
                with open(arp_file, "r") as f:
                    data = json.load(f)
                for ip, info in data.get("entries", {}).items():
                    arp[ip] = {"mac": info["mac"]}
                if arp:
                    logger.info("Loaded %d ARP entries from %s", len(arp), arp_file)
                    return arp
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.debug("Failed to read ARP file: %s", e)

        # 2. Try /proc/net/arp (Linux with --network host)
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "00:00:00:00:00:00":
                        arp[parts[0]] = {"mac": parts[3]}
        except Exception:
            pass

        # 3. Try `arp -a` (Windows and Linux)
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split("\n")
            current_iface = ""
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Windows format: "Interface: 192.168.31.66 --- 0x..."
                if "Interface:" in line:
                    current_iface = line
                    continue
                # Windows format: "  192.168.31.1    3c-cd-57-9b-db-4d     dynamic"
                parts = line.split()
                if len(parts) >= 3:
                    ip_candidate = parts[0]
                    mac_candidate = parts[1]
                    # Validate IP
                    if "." in ip_candidate and not ip_candidate.startswith("-"):
                        # Windows uses dashes, Linux uses colons
                        mac = mac_candidate.replace("-", ":").upper()
                        if mac and mac not in ("FF:FF:FF:FF:FF:FF", "(none)", "ff-ff-ff-ff-ff-ff"):
                            arp[ip_candidate] = {"mac": mac}
        except Exception:
            pass

        logger.info("ARP table: %d entries", len(arp))
        return arp

    # ── OS detection ──

    async def _get_os_info(self, ip: str) -> Optional[str]:
        if self._check_nmap():
            return await self._get_os_info_nmap(ip)
        return await self._get_os_info_scapy(ip)

    async def _get_os_info_nmap(self, ip: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._nmap_os_detect, ip)
        except Exception:
            return None

    def _nmap_os_detect(self, ip: str) -> Optional[str]:
        import nmap
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments="-O --osscan-guess -n --max-retries 1")
        except nmap.PortScannerError:
            return None
        if ip in nm.all_hosts() and "osmatch" in nm[ip]:
            osmatches = nm[ip]["osmatch"]
            if osmatches:
                return osmatches[0].get("name", "")
        return None

    async def _get_os_info_scapy(self, ip: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scapy_os_detect, ip)
        except Exception:
            return None

    def _scapy_os_detect(self, ip: str) -> Optional[str]:
        from scapy.all import IP, ICMP, sr1, conf
        conf.verb = 0
        try:
            pkt = IP(dst=ip) / ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                ttl = resp.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Network Device"
        except Exception:
            pass
        return None

    # ── Port scanning ──

    async def _scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        if self._check_nmap():
            return await self._scan_ports_nmap(ip)
        return await self._scan_ports_scapy(ip)

    async def _scan_ports_nmap(self, ip: str) -> List[Dict[str, Any]]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._nmap_scan_ports, ip)
        except Exception:
            return []

    def _nmap_scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        import nmap
        nm = nmap.PortScanner()
        # -sS works with Npcap on Windows (needs admin), -sT as fallback
        try:
            nm.scan(hosts=ip, arguments="-sS -sV --top-ports 20 -n -T4 --open --max-retries 1")
        except nmap.PortScannerError as e:
            logger.warning("Nmap port scan error for %s: %s", ip, e)
            return []
        ports = []
        if ip in nm.all_hosts() and "tcp" in nm[ip]:
            for port, info in nm[ip]["tcp"].items():
                ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": info.get("state", "open"),
                    "service": info.get("name", ""),
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                })
        return ports

    async def _scan_ports_scapy(self, ip: str) -> List[Dict[str, Any]]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scapy_port_scan, ip)
        except Exception:
            return []

    def _scapy_port_scan(self, ip: str) -> List[Dict[str, Any]]:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443,
        ]
        open_ports = []
        for port in common_ports:
            try:
                pkt = IP(dst=ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=1, verbose=0)
                if resp and resp.haslayer(TCP):
                    flags = resp[TCP].flags
                    if flags == 0x12:  # SYN-ACK
                        open_ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "",
                            "version": "",
                        })
            except Exception:
                continue
        return open_ports

    # ── Device type detection ──

    def _guess_device_type(self, ip: str, ports: List[Dict], os_info: Optional[str]) -> str:
        port_numbers = {p["port"] for p in ports}

        if self._gateway_ip and ip == self._gateway_ip:
            return "router"

        iot_ports = {1883, 1884, 8883, 5683, 9100, 5222, 5228, 11211, 2181, 9090, 18080}
        if port_numbers & iot_ports:
            return "iot"
        if len(port_numbers) >= 6:
            return "iot"

        server_ports = {80, 443, 8080, 8443, 3306, 5432, 1433, 21}
        if port_numbers & server_ports:
            return "server"

        phone_ports = {62078, 49152, 49153, 49154, 49155}
        if port_numbers & phone_ports:
            return "phone"

        pc_ports = {22, 3389, 5900}
        if port_numbers & pc_ports:
            return "pc"

        if os_info:
            os_lower = os_info.lower()
            if any(kw in os_lower for kw in ["windows", "microsoft"]):
                return "pc"
            if any(kw in os_lower for kw in ["linux", "unix", "ubuntu", "debian", "centos"]):
                return "server"
            if any(kw in os_lower for kw in ["android", "ios", "iphone", "samsung"]):
                return "phone"

        return "pc"

    # ── Hardware scanning ──

    def _scan_hardware(self, ip: str) -> Dict[str, Any]:
        """Collect hardware info from a device via WMI (Windows) or /proc (Linux)."""
        hardware: Dict[str, Any] = {
            "cpu_model": "",
            "cpu_cores": 0,
            "ram_total_gb": 0.0,
            "ram_used_gb": 0.0,
            "disk_total_gb": 0.0,
            "disk_used_gb": 0.0,
            "os_name": "",
            "os_version": "",
            "uptime_hours": 0.0,
        }

        is_local = ip in ("127.0.0.1", "::1") or ip == self._get_local_ip()

        if platform.system() == "Windows":
            self._scan_hardware_windows(hardware, is_local)
        else:
            self._scan_hardware_linux(hardware, is_local)

        return hardware

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return ""

    def _scan_hardware_windows(self, hw: Dict[str, Any], is_local: bool):
        try:
            # CPU
            r = subprocess.run(
                ["wmic", "cpu", "get", "Name,NumberOfCores", "/format:list"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                if line.startswith("Name="):
                    hw["cpu_model"] = line.split("=", 1)[1].strip()
                elif line.startswith("NumberOfCores="):
                    try:
                        hw["cpu_cores"] = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
        except Exception:
            pass

        try:
            # RAM
            r = subprocess.run(
                ["wmic", "OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory", "/format:list"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                if line.startswith("TotalVisibleMemorySize="):
                    try:
                        hw["ram_total_gb"] = round(int(line.split("=", 1)[1].strip()) / 1048576, 2)
                    except ValueError:
                        pass
                elif line.startswith("FreePhysicalMemory="):
                    try:
                        free_kb = int(line.split("=", 1)[1].strip())
                        hw["ram_used_gb"] = round(hw["ram_total_gb"] - free_kb / 1048576, 2)
                    except ValueError:
                        pass
        except Exception:
            pass

        try:
            # Disk
            r = subprocess.run(
                ["wmic", "logicaldisk", "get", "Size,FreeSpace", "/format:list"],
                capture_output=True, text=True, timeout=5,
            )
            total_bytes = 0
            free_bytes = 0
            for line in r.stdout.splitlines():
                if line.startswith("Size="):
                    try:
                        total_bytes += int(line.split("=", 1)[1].strip())
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("FreeSpace="):
                    try:
                        val = line.split("=", 1)[1].strip()
                        if val:
                            free_bytes += int(val)
                    except (ValueError, IndexError):
                        pass
            hw["disk_total_gb"] = round(total_bytes / (1024**3), 2) if total_bytes else 0.0
            hw["disk_used_gb"] = round((total_bytes - free_bytes) / (1024**3), 2) if total_bytes else 0.0
        except Exception:
            pass

        try:
            # OS + Uptime
            r = subprocess.run(
                ["wmic", "os", "get", "Caption,Version,LastBootUpTime", "/format:list"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                if line.startswith("Caption="):
                    hw["os_name"] = line.split("=", 1)[1].strip()
                elif line.startswith("Version="):
                    hw["os_version"] = line.split("=", 1)[1].strip()
                elif line.startswith("LastBootUpTime="):
                    try:
                        raw = line.split("=", 1)[1].strip()
                        # Format: YYYYMMDDHHMMSS.ffffff+UUU
                        boot_str = raw[:14]
                        boot_dt = datetime.strptime(boot_str, "%Y%m%d%H%M%S")
                        now = datetime.now()
                        hw["uptime_hours"] = round((now - boot_dt).total_seconds() / 3600, 1)
                    except Exception:
                        pass
        except Exception:
            pass

    def _scan_hardware_linux(self, hw: Dict[str, Any], is_local: bool):
        try:
            # CPU
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("model name"):
                        hw["cpu_model"] = line.split(":", 1)[1].strip()
                        break
            with open("/proc/cpuinfo", "r") as f:
                hw["cpu_cores"] = sum(1 for line in f if line.startswith("processor"))
        except Exception:
            pass

        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        kb = int(line.split()[1])
                        hw["ram_total_gb"] = round(kb / 1048576, 2)
                    elif line.startswith("MemAvailable"):
                        kb = int(line.split()[1])
                        hw["ram_used_gb"] = round(hw["ram_total_gb"] - kb / 1048576, 2)
        except Exception:
            pass

        try:
            r = subprocess.run(["df", "-B1", "/"], capture_output=True, text=True, timeout=5)
            lines = r.stdout.strip().splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                hw["disk_total_gb"] = round(int(parts[1]) / (1024**3), 2)
                hw["disk_used_gb"] = round(int(parts[2]) / (1024**3), 2)
        except Exception:
            pass

        try:
            with open("/proc/uptime", "r") as f:
                uptime_sec = float(f.read().split()[0])
                hw["uptime_hours"] = round(uptime_sec / 3600, 1)
        except Exception:
            pass

        try:
            r = subprocess.run(["uname", "-s", "-r"], capture_output=True, text=True, timeout=5)
            hw["os_name"] = r.stdout.strip()
        except Exception:
            pass

    # ── Change detection ──

    async def _detect_changes(self, device_id: int, new_hardware: Dict[str, Any]) -> List[str]:
        """Compare new hardware snapshot against the previous one. Returns list of change descriptions."""
        changes: List[str] = []
        snapshot = await get_latest_snapshot(device_id)

        if not snapshot:
            return changes

        try:
            old = json.loads(snapshot["snapshot_json"])
        except (json.JSONDecodeError, KeyError):
            return changes

        compare_fields = {
            "cpu_model": "CPU",
            "ram_total_gb": "RAM",
            "disk_total_gb": "Диск",
            "os_name": "ОС",
        }

        for field, label in compare_fields.items():
            old_val = old.get(field)
            new_val = new_hardware.get(field)
            if old_val != new_val and (old_val or new_val):
                changes.append(f"{label}: {old_val or '?'} -> {new_val or '?'}")

        old_ports = old.get("open_ports_count", 0)
        new_ports = new_hardware.get("open_ports_count", 0)
        if old_ports != new_ports:
            changes.append(f"Открытых портов: {old_ports} -> {new_ports}")

        return changes

    # ── Full device scan ──

    async def _full_scan_device(
        self, ip: str, mac: Optional[str] = None, hostname: str = "", vendor: Optional[str] = None,
        subnet: Optional[str] = None
    ) -> Dict[str, Any]:
        existing = await get_device_by_ip(ip)
        is_new = existing is None

        os_info = await self._get_os_info(ip)
        device = await upsert_device(ip=ip, mac=mac, hostname=hostname, os_guess=os_info, vendor=vendor, subnet=subnet)
        if not device:
            return {}

        ports = await self._scan_ports(ip)
        await set_ports(device["id"], ports)
        device["ports"] = ports
        device["type"] = classify_device(
            ip=ip, ports=ports, os_info=os_info,
            hostname=hostname, vendor=vendor,
            gateway_ip=self._gateway_ip,
        )

        # Hardware scanning (best-effort, may fail for remote devices without WMI/SSH)
        hardware = {}
        try:
            hardware = self._scan_hardware(ip)
            hardware["open_ports_count"] = len(ports)
        except Exception as e:
            logger.debug("Hardware scan failed for %s: %s", ip, e)

        # Run all enabled scanner modules dynamically
        scanner_context = {
            "os_guess": os_info,
            "open_ports": [p["port"] for p in ports],
            "vendor": vendor,
            "hostname": hostname,
        }
        try:
            from scanners import SCANNER_MODULES, DEFAULT_ENABLED, is_module_enabled
            for module_name, module_cls in SCANNER_MODULES.items():
                try:
                    module = module_cls()
                    if is_module_enabled(module_name):
                        module_data = await module.scan_host(ip, scanner_context)
                        if module_data:
                            hardware[f"scanner_{module_name}"] = module_data
                            logger.debug("Scanner %s collected data for %s", module_name, ip)
                except Exception as e:
                    logger.debug("Scanner module %s failed for %s: %s", module_name, ip, e)
        except ImportError:
            pass

        # Change detection
        changes = []
        if not is_new and hardware:
            changes = await self._detect_changes(device["id"], hardware)
            if changes:
                await self._emit("device_changed", {
                    "ip": ip, "hostname": hostname, "changes": changes,
                })

        # Save snapshot and hardware data
        if hardware:
            try:
                await update_device_hardware(device["id"], json.dumps(hardware, ensure_ascii=False))
                await save_device_snapshot(device["id"], json.dumps(hardware, ensure_ascii=False))
            except Exception as e:
                logger.debug("Failed to save hardware snapshot for %s: %s", ip, e)

        device["hardware"] = hardware
        return {"device": device, "is_new": is_new, "changes": changes}

    # ── Main scan orchestration ──

    async def run_scan(self, scan_type: str = "manual") -> Dict[str, Any]:
        if self.status.running:
            return {"error": "Scan already in progress"}

        self.status.running = True
        self.status.started_at = datetime.now(timezone.utc).isoformat()
        self.status.progress = 0
        self.status.devices_found = 0
        self.status.new_devices = 0
        self.status.error = ""

        # Detect ALL subnets
        subnets = self._detect_all_subnets()
        total_subnets = len(subnets)

        scan_record_id = await create_scan_record(scan_type)

        try:
            await self._emit("scan_started", {
                "scan_type": scan_type,
                "subnets": [s["subnet"] for s in subnets],
                "total_subnets": total_subnets,
                "started_at": datetime.now(timezone.utc).isoformat(),
            })

            new_devices_list = []
            all_device_ips = set()
            all_hosts = []
            devices_found = 0
            new_devices_count = 0
            total_scanned = 0

            for subnet_idx, subnet_info in enumerate(subnets):
                subnet = subnet_info["subnet"]
                gateway = subnet_info["gateway"]
                iface = subnet_info.get("interface", "")

                logger.info("Scanning subnet %d/%d: %s (gw: %s, iface: %s)",
                           subnet_idx + 1, total_subnets, subnet, gateway, iface)

                await self._emit("scan_subnet", {
                    "current": subnet_idx + 1,
                    "total": total_subnets,
                    "subnet": subnet,
                    "gateway": gateway,
                    "interface": iface,
                })

                hosts = await self._discover_hosts(subnet)
                all_hosts.extend(hosts)
                total_scanned += len(hosts)
                self.status.total = total_scanned

                logger.info("Discovered %d hosts on %s", len(hosts), subnet)

                for i, host in enumerate(hosts):
                    self.status.devices_found += 1

                    await self._emit("scan_progress", {
                        "current": self.status.devices_found,
                        "total": total_scanned,
                        "ip": host["ip"],
                        "subnet": subnet,
                        "percent": int(self.status.devices_found / max(total_scanned, 1) * 100),
                    })

                    result = await self._full_scan_device(
                        ip=host["ip"],
                        mac=host.get("mac"),
                        hostname=host.get("hostname", ""),
                        vendor=host.get("vendor"),
                        subnet=subnet,
                    )

                    if result:
                        devices_found += 1
                        all_device_ips.add(host["ip"])
                        if result.get("is_new"):
                            new_devices_count += 1
                            new_devices_list.append(host["ip"])
                            await self._emit("new_device", result["device"])

            # Mark offline devices
            existing_devices = await get_all_devices()
            for dev in existing_devices:
                if dev["ip"] not in all_device_ips and dev["status"] == "online":
                    await mark_device_offline(dev["ip"])
                    await self._emit("device_offline", {"ip": dev["ip"], "hostname": dev.get("hostname", "")})

            self.status.last_scan_at = datetime.now(timezone.utc).isoformat()
            self.status.running = False

            await finish_scan_record(
                scan_id=scan_record_id,
                devices_found=devices_found,
                new_devices=new_devices_count,
                alerts_generated=0,
            )

            result = {
                "status": "completed",
                "scan_type": self.status.scan_type,
                "subnets": [s["subnet"] for s in subnets],
                "total_subnets": total_subnets,
                "devices_found": devices_found,
                "new_devices": new_devices_count,
                "new_devices_list": new_devices_list,
                "total_hosts_scanned": total_scanned,
            }
            await self._emit("scan_completed", result)
            logger.info("Scan completed: %d devices across %d subnets", devices_found, total_subnets)
            return result

        except Exception as e:
            self.status.running = False
            self.status.error = str(e)
            logger.exception("Scan failed")
            await finish_scan_record(scan_id=scan_record_id)
            await self._emit("scan_error", {"error": str(e)})
            return {"status": "failed", "error": str(e)}

    # ── Background scan ──

    async def start_background_scan(self):
        while True:
            try:
                await self.run_scan(scan_type="auto")
            except Exception:
                logger.exception("Background scan error")
            await asyncio.sleep(self.scan_interval)

    def start(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.start_background_scan())
            logger.info("Background scanner started (interval: %ds)", self.scan_interval)

    def stop(self):
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("Background scanner stopped")


# Singleton
scanner = Scanner()
