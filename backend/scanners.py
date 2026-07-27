"""
Network scanner modules.
Each module implements a specific discovery/enrichment method.
"""
import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("netmon.scanners")


# ── Base scanner interface ──

class BaseScanner:
    """Base class for all scanner modules."""
    name: str = "base"
    description: str = ""
    requires_root: bool = False
    requires_nmap: bool = False
    enabled: bool = True

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single host. Returns enriched data dict."""
        return {}

    async def scan_subnet(self, subnet: str, hosts: List[Dict]) -> List[Dict]:
        """Scan a subnet. Returns enriched host list."""
        return hosts


# ── SNMP Scanner ──

class SNMPScanner(BaseScanner):
    name = "snmp"
    description = "SNMP: sysDescr, sysName, sysLocation, interfaces, LLDP/CDP neighbors"
    requires_nmap = True

    SNMP_COMMUNITIES = ["public", "private", "community", "manager", "admin", "snmp"]

    def _snmpwalk(self, ip: str, oid: str, community: str = "public", version: str = "2c") -> str:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", version, "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _snmpget(self, ip: str, oid: str, community: str = "public", version: str = "2c") -> str:
        try:
            result = subprocess.run(
                ["snmpget", "-v", version, "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_snmp_value(self, output: str) -> str:
        """Extract value from snmpwalk/snmpget output."""
        if "=" in output:
            parts = output.split("=", 1)
            if len(parts) > 1:
                val = parts[1].strip()
                # Remove type prefix like "STRING: ", "OID: ", etc.
                for prefix in ["STRING:", "OID:", "INTEGER:", "Gauge32:", "Timeticks:", "IpAddress:", "Hex-STRING:"]:
                    if val.startswith(prefix):
                        val = val[len(prefix):].strip().strip('"')
                return val
        return ""

    def _find_community(self, ip: str) -> Optional[str]:
        """Try to find working SNMP community string."""
        for community in self.SNMP_COMMUNITIES:
            output = self._snmpget(ip, "1.3.6.1.2.1.1.1.0", community)
            if output and "No Such" not in output and "Timeout" not in output:
                return community
        return None

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_host_sync, ip)
        except Exception as e:
            logger.debug("SNMP scan failed for %s: %s", ip, e)
            return {}

    def _scan_host_sync(self, ip: str) -> Dict[str, Any]:
        community = self._find_community(ip)
        if not community:
            return {}

        data = {
            "snmp_community": community,
            "snmp_sysdescr": self._parse_snmp_value(self._snmpget(ip, "1.3.6.1.2.1.1.1.0", community)),
            "snmp_sysname": self._parse_snmp_value(self._snmpget(ip, "1.3.6.1.2.1.1.5.0", community)),
            "snmp_syslocation": self._parse_snmp_value(self._snmpget(ip, "1.3.6.1.2.1.1.6.0", community)),
            "snmp_syscontact": self._parse_snmp_value(self._snmpget(ip, "1.3.6.1.2.1.1.4.0", community)),
            "snmp_uptime": self._parse_snmp_value(self._snmpget(ip, "1.3.6.1.2.1.1.3.0", community)),
            "snmp_interfaces": [],
            "snmp_neighbors": [],
        }

        # Walk interfaces (IF-MIB)
        iface_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.2", community)  # ifDescr
        mac_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.6", community)  # ifPhysAddress
        speed_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.5", community)  # ifSpeed
        status_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.8", community)  # ifOperStatus

        ifaces = {}
        for line in iface_output.split("\n"):
            if "ifDescr" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                ifaces.setdefault(idx, {})["name"] = self._parse_snmp_value(line)

        for line in mac_output.split("\n"):
            if "ifPhysAddress" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                ifaces.setdefault(idx, {})["mac"] = self._parse_snmp_value(line)

        for line in speed_output.split("\n"):
            if "ifSpeed" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                ifaces.setdefault(idx, {})["speed"] = self._parse_snmp_value(line)

        for line in status_output.split("\n"):
            if "ifOperStatus" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                status_val = self._parse_snmp_value(line)
                ifaces.setdefault(idx, {})["status"] = "up" if status_val == "1" else "down"

        data["snmp_interfaces"] = list(ifaces.values())

        # Walk LLDP neighbors (LLDP-MIB)
        lldp_output = self._snmpwalk(ip, "1.0.8802.1.1.2.1.4.1.1.5", community)
        for line in lldp_output.split("\n"):
            if "lldpRemSysName" in line or "lldpRemPortId" in line:
                data["snmp_neighbors"].append(self._parse_snmp_value(line))

        # Walk CDP neighbors (Cisco)
        cdp_output = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.23.1.2.1.1.4", community)
        for line in cdp_output.split("\n"):
            if line.strip():
                data["snmp_neighbors"].append(self._parse_snmp_value(line))

        logger.info("SNMP scan %s: sysname=%s, interfaces=%d, neighbors=%d",
                     ip, data.get("snmp_sysname", "?"),
                     len(data["snmp_interfaces"]), len(data["snmp_neighbors"]))
        return data


# ── WMI Scanner (Windows) ──

class WMIScanner(BaseScanner):
    name = "wmi"
    description = "WMI: CPU, RAM, disk, services, installed software (Windows)"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        os_info = context.get("os_guess", "")
        if "windows" not in os_info.lower() and "microsoft" not in os_info.lower():
            return {}
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_wmi_sync, ip)
        except Exception as e:
            logger.debug("WMI scan failed for %s: %s", ip, e)
            return {}

    def _scan_wmi_sync(self, ip: str) -> Dict[str, Any]:
        data = {
            "wmi_cpu": self._wmi_query(ip, "cpu get Name,NumberOfCores,LoadPercentage /format:csv"),
            "wmi_ram": self._wmi_query(ip, "OS get TotalVisibleMemorySize,FreePhysicalMemory /format:csv"),
            "wmi_disk": self._wmi_query(ip, "logicaldisk get DeviceID,Size,FreeSpace,FileSystem /format:csv"),
            "wmi_services": self._wmi_query(ip, "service get Name,State,DisplayName /format:csv"),
            "wmi_software": self._wmi_query(ip, "product get Name,Version /format:csv"),
            "wmi_users": self._wmi_query(ip, "useraccount get Name,FullName,Enabled /format:csv"),
            "wmi_bios": self._wmi_query(ip, "bios get Manufacturer,SerialNumber,SMBIOSBIOSVersion /format:csv"),
            "wmi_computer": self._wmi_query(ip, "computersystem get Manufacturer,Model,TotalPhysicalMemory /format:csv"),
            "wmi_network_adapters": self._wmi_query(ip, "networkadapterconfiguration get IPAddress,IPSubnet,DefaultIPGateway,MACAddress,Description,DHCPEnabled /format:csv"),
            "wmi_network_ip": self._wmi_query(ip, "networkadapter get Name,IPAddress,IPSubnet,DefaultIPGateway,MACAddress,Speed,NetConnectionStatus /format:csv"),
            "wmi_security_products": self._wmi_query(ip, "product get Name,Version,Vendor /format:csv"),
            "wmi_firewall": self._wmi_query(ip, "firewallproduct get Name,Version,PathToProductExecutable /format:csv"),
        }
        logger.info("WMI scan %s: collected %d fields", ip, len([v for v in data.values() if v]))
        return data

    def _wmi_query(self, ip: str, query: str) -> str:
        try:
            cmd = f"wmic /node:{ip} {query}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            return ""


# ── SSH Scanner (Linux) ──

class SSHScanner(BaseScanner):
    name = "ssh"
    description = "SSH: system info, CPU, RAM, disk, running services, packages"

    # Default credentials to try (for lab/SOC environments)
    DEFAULT_CREDS = [
        ("root", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("admin", ""),
    ]

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        os_info = context.get("os_guess", "")
        if any(kw in os_info.lower() for kw in ["windows", "microsoft"]):
            return {}
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_ssh_sync, ip)
        except Exception as e:
            logger.debug("SSH scan failed for %s: %s", ip, e)
            return {}

    def _scan_ssh_sync(self, ip: str) -> Dict[str, Any]:
        # Try to get system info via SSH
        cmds = {
            "ssh_hostname": "hostname",
            "ssh_uptime": "uptime -p 2>/dev/null || uptime",
            "ssh_cpu": "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2 | xargs",
            "ssh_cpu_cores": "nproc",
            "ssh_ram_total": "free -b | awk '/Mem:/{print $2}'",
            "ssh_ram_used": "free -b | awk '/Mem:/{print $3}'",
            "ssh_disk": "df -B1 / | tail -1 | awk '{print $2, $3, $4}'",
            "ssh_kernel": "uname -r",
            "ssh_os": "cat /etc/os-release 2>/dev/null | head -2",
            "ssh_net_interfaces": "ip -4 addr show | grep inet | awk '{print $2, $NF}'",
            "ssh_arp": "arp -a 2>/dev/null | head -20",
            "ssh_listening": "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20",
            "ssh_routes": "ip route 2>/dev/null | head -10",
            "ssh_dmesg": "dmesg | tail -10 2>/dev/null",
            "ssh_packages": "dpkg -l 2>/dev/null | head -30 || rpm -qa 2>/dev/null | head -30 || apk list --installed 2>/dev/null | head -30",
            "ssh_users": "cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v /bin/false | cut -d: -f1",
            "ssh_docker": "docker ps 2>/dev/null || true",
        }

        data = {}
        for key, cmd in cmds.items():
            output = self._ssh_cmd(ip, cmd)
            if output:
                data[key] = output.strip()

        logger.info("SSH scan %s: collected %d fields", ip, len(data))
        return data

    def _ssh_cmd(self, ip: str, cmd: str) -> str:
        try:
            # Try passwordless first
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                 "-o", "BatchMode=yes", f"root@{ip}", cmd],
                capture_output=True, text=True, timeout=8,
            )
            if result.returncode == 0:
                return result.stdout

            # Try with common creds
            for user, password in self.DEFAULT_CREDS:
                if not password:
                    continue
                try:
                    result = subprocess.run(
                        ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=3", f"{user}@{ip}", cmd],
                        capture_output=True, text=True, timeout=8,
                    )
                    if result.returncode == 0:
                        return result.stdout
                except FileNotFoundError:
                    break  # sshpass not installed
        except Exception:
            pass
        return ""


# ── mDNS/Bonjour Scanner ──

class MDNSScanner(BaseScanner):
    name = "mdns"
    description = "mDNS/Bonjour: Apple devices, IoT, printers"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        # mDNS is typically done via multicast, not per-host
        # We'll use nmap's mdns script or avahi-browse
        return {}

    async def scan_subnet(self, subnet: str, hosts: List[Dict]) -> List[Dict]:
        """Use avahi-browse or nmap mdns script to discover mDNS services."""
        try:
            loop = asyncio.get_event_loop()
            mdns_hosts = await loop.run_in_executor(None, self._scan_mdns_sync)
            # Merge mDNS data into existing hosts
            ip_map = {h["ip"]: h for h in hosts}
            for mdns_host in mdns_hosts:
                ip = mdns_host.get("ip")
                if ip in ip_map:
                    ip_map[ip].update({k: v for k, v in mdns_host.items() if v})
            return list(ip_map.values())
        except Exception as e:
            logger.debug("mDNS scan failed: %s", e)
            return hosts

    def _scan_mdns_sync(self) -> List[Dict]:
        hosts = []
        try:
            # Try avahi-browse
            result = subprocess.run(
                ["avahi-browse", "-a", "-t", "-p", "-r"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                current = {}
                for line in result.stdout.split("\n"):
                    if line.startswith("="):
                        if current.get("ip"):
                            hosts.append(current)
                        current = {}
                    elif ";IPv4;" in line and "address" in line.lower():
                        parts = line.split(";")
                        if len(parts) >= 4:
                            current["ip"] = parts[3]
                    elif "hostname" in line.lower():
                        parts = line.split(";")
                        if len(parts) >= 4:
                            current["mdns_hostname"] = parts[3].strip()
                    elif "txt" in line.lower() and "model" in line.lower():
                        parts = line.split(";")
                        if len(parts) >= 4:
                            current["mdns_model"] = parts[3].strip()
                if current.get("ip"):
                    hosts.append(current)
        except FileNotFoundError:
            # Try nmap mdns script
            try:
                result = subprocess.run(
                    ["nmap", "--script", "mdns-info", "-sn", "-n", "--open"],
                    capture_output=True, text=True, timeout=30,
                )
                # Parse nmap mdns output
                current_ip = None
                for line in result.stdout.split("\n"):
                    if "Nmap scan report for" in line:
                        parts = line.split("(")
                        if len(parts) > 1:
                            current_ip = parts[1].rstrip(")")
                    elif "mdns" in line.lower() and current_ip:
                        hosts.append({"ip": current_ip, "mdns_info": line.strip()})
            except Exception:
                pass
        except Exception:
            pass
        return hosts


# ── UPnP/SSDP Scanner ──

class UPnPScanner(BaseScanner):
    name = "upnp"
    description = "UPnP/SSDP: Smart home devices, media servers, IoT"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_upnp_sync, ip)
        except Exception:
            return {}

    def _scan_upnp_sync(self, ip: str) -> Dict[str, Any]:
        """Send SSDP M-SEARCH and parse response."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(2)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 3\r\n"
                "\r\n"
            )
            sock.sendto(ssdp_request.encode(), (ip, 1900))
            data, _ = sock.recvfrom(4096)
            sock.close()

            response = data.decode("utf-8", errors="ignore")
            result = {}
            for line in response.split("\r\n"):
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "server":
                        result["upnp_server"] = val
                    elif key == "st":
                        result["upnp_type"] = val
                    elif key == "location":
                        result["upnp_location"] = val
                    elif key == "usn":
                        result["upnp_usn"] = val

            if result:
                logger.info("UPnP scan %s: found %s", ip, result.get("upnp_type", "?"))
            return result
        except Exception:
            return {}


# ── SMB/NetBIOS Scanner ──

class SMBScanner(BaseScanner):
    name = "smb"
    description = "SMB/NetBIOS: Windows domain info, shares, OS version"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_smb_sync, ip)
        except Exception:
            return {}

    def _scan_smb_sync(self, ip: str) -> Dict[str, Any]:
        data = {}

        # nbtstat / nmap smb scripts
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if "UNIQUE" in line or "GROUP" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            data.setdefault("netbios_names", []).append({
                                "name": parts[0], "type": parts[1] if len(parts) > 1 else ""
                            })
            else:
                # Use nmap smb scripts
                result = subprocess.run(
                    ["nmap", "-sU", "-sT", "-p", "U:137,T:139,T:445", "--script",
                     "smb-os-discovery,smb-enum-shares,smb-enum-users", "-n", ip],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.split("\n"):
                    if "smb-os-discovery" in line:
                        data["smb_os"] = line.split(":", 1)[-1].strip() if ":" in line else ""
                    elif "smb-enum-shares" in line and "Disk" in line:
                        data.setdefault("smb_shares", []).append(line.strip())
                    elif "smb-enum-users" in line:
                        data.setdefault("smb_users", []).append(line.strip())
        except Exception:
            pass

        return data


# ── HTTP Prober ──

class HTTPProber(BaseScanner):
    name = "http"
    description = "HTTP: Service fingerprinting, title extraction, headers"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        ports = context.get("open_ports", [])
        http_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8000, 3000, 5000, 8001, 8888]]
        if not http_ports:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_http_sync, ip, http_ports)
        except Exception:
            return {}

    def _scan_http_sync(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        data = {"http_services": []}
        for port in ports:
            scheme = "https" if port in [443, 8443] else "http"
            try:
                result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{content_type}|%{redirect_url}",
                     "-m", "3", "-k", f"{scheme}://{ip}:{port}/"],
                    capture_output=True, text=True, timeout=5,
                )
                parts = result.stdout.split("|")
                if len(parts) >= 2 and parts[0].strip().startswith("2"):
                    svc = {"port": port, "scheme": scheme, "status": parts[0].strip()}
                    # Get title
                    try:
                        title_result = subprocess.run(
                            ["curl", "-s", "-m", "3", "-k", f"{scheme}://{ip}:{port}/"],
                            capture_output=True, text=True, timeout=5,
                        )
                        if "<title>" in title_result.stdout.lower():
                            start = title_result.stdout.lower().index("<title>") + 7
                            end = title_result.stdout.lower().index("</title>", start)
                            svc["title"] = title_result.stdout[start:end].strip()[:100]
                    except Exception:
                        pass
                    data["http_services"].append(svc)
            except Exception:
                continue
        return data


# ── Nmap NSE Scripts Scanner ──

class NmapNSEScanner(BaseScanner):
    name = "nse"
    description = "Nmap NSE scripts: OS detection, vuln scan, service enumeration"
    requires_nmap = True

    def __init__(self):
        self._nmap_path = None
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self._nmap_path = "nmap"
        except Exception:
            pass

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if not self._nmap_path:
            return {}
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_nse_sync, ip)
        except Exception:
            return {}

    def _scan_nse_sync(self, ip: str) -> Dict[str, Any]:
        data = {"nse_scripts": []}

        # OS detection with -O
        try:
            result = subprocess.run(
                ["nmap", "-O", "--osscan-guess", "-n", "--max-retries", "1", ip],
                capture_output=True, text=True, timeout=20,
            )
            for line in result.stdout.split("\n"):
                if "Device type:" in line:
                    data["nse_device_type"] = line.split(":", 1)[-1].strip()
                elif "Running:" in line:
                    data["nse_running"] = line.split(":", 1)[-1].strip()
                elif "OS details:" in line or "Aggressive OS guesses:" in line:
                    data["nse_os_details"] = line.split(":", 1)[-1].strip()
                elif "Uptime guess:" in line:
                    data["nse_uptime"] = line.split(":", 1)[-1].strip()
                elif "Network Distance:" in line:
                    data["nse_network_distance"] = line.split(":", 1)[-1].strip()
        except Exception:
            pass

        # Service version detection with -sV on key ports
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--top-ports", "20", "-n", "-T4", "--max-retries", "1", ip],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.split("\n"):
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        data["nse_scripts"].append({
                            "port": parts[0],
                            "service": parts[2] if len(parts) > 2 else "",
                            "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                        })
        except Exception:
            pass

        return data


# ── Registry Scanner (Windows via nmap) ──

class RegistryScanner(BaseScanner):
    name = "registry"
    description = "Windows Registry: installed software, system config (via SMB)"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        os_info = context.get("os_guess", "")
        if not any(kw in os_info.lower() for kw in ["windows", "microsoft"]):
            return {}
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_registry_sync, ip)
        except Exception:
            return {}

    def _scan_registry_sync(self, ip: str) -> Dict[str, Any]:
        data = {}
        try:
            # Use nmap smb-reg-shell or similar
            result = subprocess.run(
                ["nmap", "--script", "smb-os-discovery", "-p", "445", "-n", ip],
                capture_output=True, text=True, timeout=15,
            )
            for line in result.stdout.split("\n"):
                if "OS:" in line:
                    data["windows_os"] = line.split(":", 1)[-1].strip()
                elif "Server:" in line:
                    data["windows_server"] = line.split(":", 1)[-1].strip()
                elif "Domain:" in line:
                    data["windows_domain"] = line.split(":", 1)[-1].strip()
                elif "Workgroup:" in line:
                    data["windows_workgroup"] = line.split(":", 1)[-1].strip()
        except Exception:
            pass
        return data


# ── LLDP/CDP Neighbor Scanner ──

class LLDPScanner(BaseScanner):
    name = "lldp"
    description = "LLDP/CDP: network neighbor discovery via SNMP (switches, routers)"
    requires_nmap = True

    def _snmpwalk(self, ip: str, oid: str, community: str = "public") -> str:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_val(self, output: str) -> str:
        if "=" in output:
            val = output.split("=", 1)[1].strip()
            for prefix in ["STRING:", "OID:", "INTEGER:", "Gauge32:", "IpAddress:", "Hex-STRING:"]:
                if val.startswith(prefix):
                    val = val[len(prefix):].strip().strip('"')
            return val
        return ""

    def _find_community(self, ip: str) -> Optional[str]:
        for community in ["public", "private", "community", "admin"]:
            output = self._snmpwalk(ip, "1.3.6.1.2.1.1.1.0", community)
            if output and "No Such" not in output and "Timeout" not in output:
                return community
        return None

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_lldp_sync, ip)
        except Exception as e:
            logger.debug("LLDP scan failed for %s: %s", ip, e)
            return {}

    def _scan_lldp_sync(self, ip: str) -> Dict[str, Any]:
        community = self._find_community(ip)
        if not community:
            return {}

        neighbors = []

        # LLDP-MIB: walk lldpRemSysName, lldpRemPortId, lldpRemManAddrIfId
        lldp_names = self._snmpwalk(ip, "1.0.8802.1.1.2.1.4.1.1.5", community)
        lldp_ports = self._snmpwalk(ip, "1.0.8802.1.1.2.1.4.1.1.7", community)
        lldp_addrs = self._snmpwalk(ip, "1.0.8802.1.1.2.1.4.2.1.4", community)

        name_map = {}
        for line in lldp_names.split("\n"):
            if "lldpRemSysName" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                name_map[idx] = self._parse_val(line)

        port_map = {}
        for line in lldp_ports.split("\n"):
            if "lldpRemPortId" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                port_map[idx] = self._parse_val(line)

        addr_map = {}
        for line in lldp_addrs.split("\n"):
            if "lldpRemManAddrIfId" in line or "lldpRemManAddr" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                addr_map[idx] = self._parse_val(line)

        for idx in set(list(name_map.keys()) + list(port_map.keys())):
            neighbors.append({
                "neighbor_name": name_map.get(idx, ""),
                "neighbor_port": port_map.get(idx, ""),
                "neighbor_ip": addr_map.get(idx, ""),
                "protocol": "LLDP",
            })

        # CDP-MIB (Cisco): walk cdpCacheDeviceId, cdpCacheDevicePort, cdpCachePlatform
        cdp_names = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.23.1.2.1.1.6", community)
        cdp_ports = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.23.1.2.1.1.7", community)
        cdp_platforms = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.23.1.2.1.1.8", community)
        cdp_addrs = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.23.1.2.1.1.4", community)

        cdp_name_map = {}
        for line in cdp_names.split("\n"):
            if "cdpCacheDeviceId" in line:
                idx = line.split("=", 1)[0].split(".")[-2].strip()
                cdp_name_map[idx] = self._parse_val(line)

        cdp_port_map = {}
        for line in cdp_ports.split("\n"):
            if "cdpCacheDevicePort" in line:
                idx = line.split("=", 1)[0].split(".")[-2].strip()
                cdp_port_map[idx] = self._parse_val(line)

        cdp_plat_map = {}
        for line in cdp_platforms.split("\n"):
            if "cdpCachePlatform" in line:
                idx = line.split("=", 1)[0].split(".")[-2].strip()
                cdp_plat_map[idx] = self._parse_val(line)

        for idx in set(list(cdp_name_map.keys()) + list(cdp_port_map.keys())):
            neighbors.append({
                "neighbor_name": cdp_name_map.get(idx, ""),
                "neighbor_port": cdp_port_map.get(idx, ""),
                "neighbor_platform": cdp_plat_map.get(idx, ""),
                "protocol": "CDP",
            })

        if neighbors:
            logger.info("LLDP/CDP scan %s: found %d neighbors", ip, len(neighbors))
        return {"lldp_neighbors": neighbors}


# ── ARP Table Scanner ──

class ARPScanner(BaseScanner):
    name = "arp"
    description = "ARP: local ARP table — IP/MAC mappings, interfaces, entry types"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_arp_sync, ip)
        except Exception as e:
            logger.debug("ARP scan failed for %s: %s", ip, e)
            return {}

    def _scan_arp_sync(self, ip: str) -> Dict[str, Any]:
        entries = []

        # Try /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[2] != "00:00:00:00:00:00":
                        entries.append({
                            "ip": parts[0],
                            "mac": parts[3],
                            "interface": parts[5],
                            "type": "dynamic" if parts[2] != "00:00:00:00:00:00" else "static",
                        })
        except (FileNotFoundError, PermissionError):
            pass

        # Try `arp -a` (Windows/Linux)
        if not entries:
            try:
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=5,
                )
                current_iface = ""
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if "Interface:" in line:
                        current_iface = line
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        ip_c = parts[0]
                        mac_c = parts[1]
                        if "." in ip_c and not ip_c.startswith("-"):
                            mac = mac_c.replace("-", ":").upper()
                            if mac and mac not in ("FF:FF:FF:FF:FF:FF", "(none)"):
                                entry_type = parts[2] if len(parts) > 2 else "dynamic"
                                entries.append({
                                    "ip": ip_c,
                                    "mac": mac,
                                    "interface": current_iface,
                                    "type": entry_type,
                                })
            except Exception:
                pass

        if entries:
            logger.info("ARP scan %s: found %d entries", ip, len(entries))
        return {"arp_table": entries}


# ── DHCP Scanner ──

class DHCPScanner(BaseScanner):
    name = "dhcp"
    description = "DHCP: lease info, MAC/IP bindings, hostnames"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_dhcp_sync, ip)
        except Exception as e:
            logger.debug("DHCP scan failed for %s: %s", ip, e)
            return {}

    def _scan_dhcp_sync(self, ip: str) -> Dict[str, Any]:
        data = {"dhcp_leases": []}

        # Windows: ipconfig /all for DHCP info
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["ipconfig", "/all"], capture_output=True, text=True, timeout=5,
                )
                current_adapter = ""
                for line in result.stdout.split("\n"):
                    if "adapter" in line.lower():
                        current_adapter = line.strip().rstrip(":")
                    if "DHCP" in line and "Enabled" in line:
                        data["dhcp_enabled"] = "Yes" in line
                    elif "DHCP Server" in line and ":" in line:
                        data["dhcp_server"] = line.split(":")[-1].strip()
                    elif "Lease Obtained" in line and ":" in line:
                        data["dhcp_lease_obtained"] = line.split(":")[-1].strip()
                    elif "Lease Expires" in line and ":" in line:
                        data["dhcp_lease_expires"] = line.split(":")[-1].strip()
            except Exception:
                pass

        # Linux: parse lease files
        lease_files = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/dhcpd/dhcpd.leases",
            "/var/lib/NetworkManager/dhclient-*.leases",
            "/var/lib/dhclient/dhclient.leases",
        ]
        import glob
        for pattern in lease_files:
            for lease_file in glob.glob(pattern):
                try:
                    with open(lease_file, "r") as f:
                        content = f.read()
                    lease = {}
                    for line in content.split("\n"):
                        line = line.strip()
                        if line.startswith("lease") and "{" in line:
                            lease = {}
                        elif "interface" in line:
                            lease["interface"] = line.split('"')[-2] if '"' in line else ""
                        elif "fixed-address" in line:
                            lease["ip"] = line.split()[-1].rstrip(";")
                        elif "option routers" in line or "option routers" in line:
                            lease["gateway"] = line.split()[-1].rstrip(";")
                        elif "option host-name" in line:
                            lease["hostname"] = line.split('"')[-2] if '"' in line else ""
                        elif "option domain-name-servers" in line:
                            lease["dns"] = line.split()[-1].rstrip(";")
                        elif line == "}":
                            if lease.get("ip"):
                                data["dhcp_leases"].append(lease)
                            lease = {}
                except (FileNotFoundError, PermissionError):
                    pass

        # SNMP walk of DHCP-MIB on router
        try:
            for community in ["public", "private"]:
                result = subprocess.run(
                    ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", ip,
                     "1.3.6.1.4.1.14698.100.1.1"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout and "No Such" not in result.stdout:
                    for line in result.stdout.split("\n"):
                        if line.strip():
                            data.setdefault("dhcp_snmp_entries", []).append(line.strip())
                    break
        except Exception:
            pass

        if data["dhcp_leases"]:
            logger.info("DHCP scan %s: found %d leases", ip, len(data["dhcp_leases"]))
        return data


# ── VLAN Scanner ──

class VLANScanner(BaseScanner):
    name = "vlan"
    description = "VLAN: VLAN membership, port-to-VLAN mappings (switches)"
    requires_nmap = True

    def _snmpwalk(self, ip: str, oid: str, community: str = "public") -> str:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_val(self, output: str) -> str:
        if "=" in output:
            val = output.split("=", 1)[1].strip()
            for prefix in ["STRING:", "OID:", "INTEGER:", "Gauge32:", "Timeticks:", "Hex-STRING:"]:
                if val.startswith(prefix):
                    val = val[len(prefix):].strip().strip('"')
            return val
        return ""

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_vlan_sync, ip)
        except Exception as e:
            logger.debug("VLAN scan failed for %s: %s", ip, e)
            return {}

    def _scan_vlan_sync(self, ip: str) -> Dict[str, Any]:
        data = {"vlans": [], "vlan_ports": {}}

        for community in ["public", "private"]:
            # IEEE8021-Q-BRIDGE-MIB: vlan names
            vlan_names = self._snmpwalk(ip, "1.3.6.1.2.1.17.7.1.4.5.1.1", community)
            if vlan_names and "No Such" not in vlan_names:
                for line in vlan_names.split("\n"):
                    if "dot1qVlanStaticName" in line or "17.7.1.4.5.1.1" in line:
                        parts = line.split("=", 1)
                        if len(parts) > 1:
                            # Extract VLAN ID from OID
                            oid_part = parts[0].strip()
                            vlan_id = oid_part.split(".")[-1] if "." in oid_part else ""
                            vlan_name = self._parse_val(line)
                            if vlan_id:
                                data["vlans"].append({"vlan_id": vlan_id, "name": vlan_name})

            # IEEE8021-MIB: port-to-VLAN
            pvid_output = self._snmpwalk(ip, "1.3.6.1.2.1.17.1.4.1.1", community)
            if pvid_output and "No Such" not in pvid_output:
                for line in pvid_output.split("\n"):
                    if "dot1qPvid" in line:
                        parts = line.split("=", 1)
                        if len(parts) > 1:
                            oid_part = parts[0].strip()
                            port_id = oid_part.split(".")[-1] if "." in oid_part else ""
                            vlan_id = self._parse_val(line)
                            if port_id and vlan_id:
                                data["vlan_ports"].setdefault(vlan_id, []).append(port_id)

            # Try BRIDGE-MIB: VLAN membership (Cisco-style)
            vlan_membership = self._snmpwalk(ip, "1.3.6.1.4.1.9.9.68.1.2.2.1.2", community)
            if vlan_membership and "No Such" not in vlan_membership:
                for line in vlan_membership.split("\n"):
                    if line.strip():
                        data.setdefault("vlan_membership_raw", []).append(line.strip())

            if data["vlans"]:
                break

        if data["vlans"]:
            logger.info("VLAN scan %s: found %d VLANs", ip, len(data["vlans"]))
        return data


# ── Traceroute Scanner ──

class TracerouteScanner(BaseScanner):
    name = "traceroute"
    description = "Traceroute: hop-by-hop path to each discovered host"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_traceroute_sync, ip)
        except Exception as e:
            logger.debug("Traceroute failed for %s: %s", ip, e)
            return {}

    def _scan_traceroute_sync(self, ip: str) -> Dict[str, Any]:
        hops = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tracert", "-d", "-w", "1000", "-h", "15", ip],
                    capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("Tracing") or line.startswith("Over"):
                        continue
                    parts = line.split()
                    # Windows format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                    if len(parts) >= 4:
                        try:
                            ttl = int(parts[0])
                        except ValueError:
                            continue
                        # Find IP (last valid-looking part)
                        host_ip = ""
                        latencies = []
                        for p in parts[1:]:
                            if "." in p and not p.startswith("<"):
                                host_ip = p
                            elif "ms" in p or p == "*":
                                latencies.append(p)
                        # Calculate avg latency
                        avg_ms = ""
                        ms_vals = [l.replace("ms", "").replace("<", "").strip() for l in latencies if "ms" in l]
                        if ms_vals:
                            try:
                                avg_ms = str(round(sum(float(v) for v in ms_vals) / len(ms_vals), 1))
                            except ValueError:
                                pass
                        if host_ip or "* * *" in line:
                            hops.append({
                                "ttl": ttl,
                                "ip": host_ip or "*",
                                "latency_ms": avg_ms or "*",
                            })
            else:
                result = subprocess.run(
                    ["traceroute", "-n", "-w", "1", "-m", "15", ip],
                    capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ttl = int(parts[0])
                        except ValueError:
                            continue
                        host_ip = parts[1] if parts[1] != "*" else "*"
                        ms_vals = [p.replace("ms", "").strip() for p in parts[2:] if "ms" in p]
                        avg_ms = ""
                        if ms_vals:
                            try:
                                avg_ms = str(round(sum(float(v) for v in ms_vals) / len(ms_vals), 1))
                            except ValueError:
                                pass
                        hops.append({"ttl": ttl, "ip": host_ip, "latency_ms": avg_ms or "*"})
        except Exception:
            pass

        if hops:
            logger.info("Traceroute %s: %d hops", ip, len(hops))
        return {"traceroute": hops}


# ── SNMP Real-time Polling Scanner ──

class SNMPPollingScanner(BaseScanner):
    name = "snmp_polling"
    description = "SNMP polling: CPU load, disk usage, uptime, process count, interface traffic"
    requires_nmap = True

    def _snmpwalk(self, ip: str, oid: str, community: str = "public") -> str:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_val(self, output: str) -> str:
        if "=" in output:
            val = output.split("=", 1)[1].strip()
            for prefix in ["STRING:", "OID:", "INTEGER:", "Gauge32:", "Timeticks:", "Counter32:", "Counter64:", "IpAddress:"]:
                if val.startswith(prefix):
                    val = val[len(prefix):].strip().strip('"')
            return val
        return ""

    def _find_community(self, ip: str) -> Optional[str]:
        for community in ["public", "private", "community", "admin"]:
            output = self._snmpwalk(ip, "1.3.6.1.2.1.1.1.0", community)
            if output and "No Such" not in output and "Timeout" not in output:
                return community
        return None

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_snmp_poll_sync, ip)
        except Exception as e:
            logger.debug("SNMP polling failed for %s: %s", ip, e)
            return {}

    def _scan_snmp_poll_sync(self, ip: str) -> Dict[str, Any]:
        community = self._find_community(ip)
        if not community:
            return {}

        data = {}

        # HOST-RESOURCES-MIB: hrProcessorLoad (CPU per core)
        cpu_output = self._snmpwalk(ip, "1.3.6.1.2.1.25.3.3.1.2", community)
        cpu_loads = []
        for line in cpu_output.split("\n"):
            if "hrProcessorLoad" in line:
                val = self._parse_val(line)
                try:
                    cpu_loads.append(int(val))
                except (ValueError, TypeError):
                    pass
        if cpu_loads:
            data["cpu_load_per_core"] = cpu_loads
            data["cpu_load_avg"] = round(sum(cpu_loads) / len(cpu_loads), 1)

        # hrSystemUptime
        uptime_output = self._snmpwalk(ip, "1.3.6.1.2.1.25.1.3.0", community)
        if uptime_output:
            uptime_val = self._parse_val(uptime_output)
            data["uptime_raw"] = uptime_val

        # hrSystemProcesses
        procs_output = self._snmpwalk(ip, "1.3.6.1.2.1.25.1.6.0", community)
        if procs_output:
            procs_val = self._parse_val(procs_output)
            try:
                data["processes_count"] = int(procs_val)
            except (ValueError, TypeError):
                pass

        # hrStorageTable (disk usage)
        storage_desc = self._snmpwalk(ip, "1.3.6.1.2.1.25.2.3.1.3", community)
        storage_size = self._snmpwalk(ip, "1.3.6.1.2.1.25.2.3.1.5", community)
        storage_used = self._snmpwalk(ip, "1.3.6.1.2.1.25.2.3.1.6", community)

        desc_map = {}
        for line in storage_desc.split("\n"):
            if "hrStorageDescr" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                desc_map[idx] = self._parse_val(line)

        storages = []
        for line in storage_size.split("\n"):
            if "hrStorageSize" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                try:
                    size_kb = int(self._parse_val(line))
                    desc = desc_map.get(idx, "")
                    storages.append({"description": desc, "size_kb": size_kb, "used_kb": 0})
                except (ValueError, TypeError):
                    pass

        for line in storage_used.split("\n"):
            if "hrStorageUsed" in line:
                idx = line.split("=", 1)[0].split(".")[-1].strip()
                try:
                    used_kb = int(self._parse_val(line))
                    for s in storages:
                        if s["description"] == desc_map.get(idx, ""):
                            s["used_kb"] = used_kb
                            break
                except (ValueError, TypeError):
                    pass
        if storages:
            data["disk_usage"] = storages

        # IF-MIB: interface traffic counters
        if_name = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.2", community)
        if_in = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.10", community)
        if_out = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.16", community)
        if_speed = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.5", community)

        ifaces = {}
        for line in if_name.split("\n"):
            if "ifDescr" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                ifaces.setdefault(idx, {})["name"] = self._parse_val(line)

        for line in if_in.split("\n"):
            if "ifInOctets" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["in_octets"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        for line in if_out.split("\n"):
            if "ifOutOctets" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["out_octets"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        for line in if_speed.split("\n"):
            if "ifSpeed" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["speed_bps"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        data["interface_traffic"] = list(ifaces.values())

        logger.info("SNMP polling %s: cpu=%s, procs=%s",
                     ip, data.get("cpu_load_avg"), data.get("processes_count"))
        return data


# ── Vulnerability Scanner (Nmap NSE) ──

class VulnScanner(BaseScanner):
    name = "vuln"
    description = "Vulnerability scan: Nmap NSE vuln scripts, CVE detection"
    requires_nmap = True

    def __init__(self):
        self._nmap_path = None
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self._nmap_path = "nmap"
        except Exception:
            pass

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if not self._nmap_path:
            return {}
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_vuln_sync, ip, context.get("open_ports", []))
        except Exception as e:
            logger.debug("Vuln scan failed for %s: %s", ip, e)
            return {}

    def _scan_vuln_sync(self, ip: str, open_ports: List[int]) -> Dict[str, Any]:
        data = {"vulnerabilities": [], "ssl_cert_info": {}}

        # Run vuln scripts on open ports
        port_str = ",".join(str(p) for p in open_ports[:10]) if open_ports else "21,22,80,443,445,3389"
        try:
            result = subprocess.run(
                ["nmap", "--script", "vuln", "-p", port_str, "-n", "-T4", "--max-retries", "1", ip],
                capture_output=True, text=True, timeout=60,
            )
            current_vuln = ""
            for line in result.stdout.split("\n"):
                line = line.strip()
                # CVE entries: "| cve-XXXX-XXXXX: ..."
                if "cve-" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        cve_id = parts[0].replace("|", "").strip()
                        desc = parts[1].strip()
                        data["vulnerabilities"].append({
                            "cve_id": cve_id,
                            "description": desc[:200],
                        })
                # VULNERABLE marker
                elif "VULNERABLE" in line:
                    data["vulnerabilities"].append({
                        "status": "VULNERABLE",
                        "detail": line,
                    })
                # State
                elif "State:" in line and data["vulnerabilities"]:
                    data["vulnerabilities"][-1]["state"] = line.split(":", 1)[-1].strip()
        except Exception:
            pass

        # SSL cert info on 443
        if 443 in open_ports or not open_ports:
            try:
                result = subprocess.run(
                    ["nmap", "--script", "ssl-cert,ssl-enum-ciphers", "-p", "443", "-n", ip],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "Issuer:" in line:
                        data["ssl_cert_info"]["issuer"] = line.split(":", 1)[-1].strip()
                    elif "Subject:" in line:
                        data["ssl_cert_info"]["subject"] = line.split(":", 1)[-1].strip()
                    elif "Not valid before:" in line:
                        data["ssl_cert_info"]["valid_from"] = line.split(":", 1)[-1].strip()
                    elif "Not valid after:" in line:
                        data["ssl_cert_info"]["valid_to"] = line.split(":", 1)[-1].strip()
                    elif "Serial Number:" in line:
                        data["ssl_cert_info"]["serial"] = line.split(":", 1)[-1].strip()
            except Exception:
                pass

        if data["vulnerabilities"]:
            logger.info("Vuln scan %s: found %d vulns", ip, len(data["vulnerabilities"]))
        return data


# ── SSL Certificate Scanner ──

class SSLScanner(BaseScanner):
    name = "ssl"
    description = "SSL/TLS: certificate details, expiry, protocol, cipher suite"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        open_ports = context.get("open_ports", [])
        ssl_ports = [p for p in open_ports if p in [443, 8443, 993, 995, 465, 636]]
        if not ssl_ports:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_ssl_sync, ip, ssl_ports)
        except Exception as e:
            logger.debug("SSL scan failed for %s: %s", ip, e)
            return {}

    def _scan_ssl_sync(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        data = {"ssl_certs": {}}

        for port in ports:
            cert_info = {}
            try:
                # Use Python ssl module
                import ssl
                import datetime
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((ip, port), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        if cert:
                            import cryptography.x509
                            x509 = cryptography.x509.load_der_x509_certificate(cert)
                            cert_info["issuer"] = ", ".join(
                                f"{attr.oid._name}={attr.value}"
                                for attr in x509.issuer
                            )
                            cert_info["subject"] = ", ".join(
                                f"{attr.oid._name}={attr.value}"
                                for attr in x509.subject
                            )
                            cert_info["valid_from"] = x509.not_valid_before.isoformat()
                            cert_info["valid_to"] = x509.not_valid_after.isoformat()
                            cert_info["serial"] = format(x509.serial_number, 'x')
                            cert_info["protocol"] = ssock.version()
                            cert_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

                            # Calculate days remaining
                            days_left = (x509.not_valid_after - datetime.datetime.now(datetime.timezone.utc)).days
                            cert_info["days_remaining"] = days_left
            except ImportError:
                # No cryptography module, try openssl CLI
                try:
                    result = subprocess.run(
                        ["openssl", "s_client", "-connect", f"{ip}:{port}", "-servername", ip],
                        input="", capture_output=True, text=True, timeout=5,
                    )
                    cert_pem = result.stdout
                    if "BEGIN CERTIFICATE" in cert_pem:
                        result2 = subprocess.run(
                            ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-serial"],
                            input=cert_pem, capture_output=True, text=True, timeout=5,
                        )
                        for line in result2.stdout.split("\n"):
                            if line.startswith("notBefore="):
                                cert_info["valid_from"] = line.split("=", 1)[1]
                            elif line.startswith("notAfter="):
                                cert_info["valid_to"] = line.split("=", 1)[1]
                            elif line.startswith("subject="):
                                cert_info["subject"] = line.split("=", 1)[1]
                            elif line.startswith("issuer="):
                                cert_info["issuer"] = line.split("=", 1)[1]
                            elif line.startswith("serial="):
                                cert_info["serial"] = line.split("=", 1)[1]
                except Exception:
                    pass
            except Exception:
                pass

            if cert_info:
                data["ssl_certs"][str(port)] = cert_info

        if data["ssl_certs"]:
            logger.info("SSL scan %s: found certs on %d ports", ip, len(data["ssl_certs"]))
        return data


# ── MQTT Scanner ──

class MQTTScanner(BaseScanner):
    name = "mqtt"
    description = "MQTT: broker discovery, topic enumeration, client info"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        open_ports = context.get("open_ports", [])
        mqtt_ports = [p for p in open_ports if p in [1883, 8883]]
        if not mqtt_ports:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_mqtt_sync, ip, mqtt_ports)
        except Exception as e:
            logger.debug("MQTT scan failed for %s: %s", ip, e)
            return {}

    def _scan_mqtt_sync(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        data = {"mqtt_topics": [], "mqtt_broker_info": {}}

        for port in ports:
            try:
                import struct
                # Build MQTT CONNECT packet for anonymous connection
                client_id = "netmon_probe"
                # Variable header: protocol name "MQTT", level 4, clean session, keepalive 60
                var_header = b"\x00\x04MQTT\x04\x02\x00\x3c"
                # Payload: client ID
                payload = struct.pack("!H", len(client_id)) + client_id.encode()
                # Fixed header: CONNECT (0x10) + remaining length
                remaining = len(var_header) + len(payload)
                fixed_header = bytes([0x10]) + self._encode_remaining_length(remaining)

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                sock.sendall(fixed_header + var_header + payload)

                # Read CONNACK
                response = sock.recv(1024)
                sock.close()

                if len(response) >= 4 and response[0] == 0x20:
                    rc = response[3]
                    data["mqtt_broker_info"]["port"] = port
                    data["mqtt_broker_info"]["connect_return_code"] = rc
                    data["mqtt_broker_info"]["accessible"] = rc == 0

                    # Try to subscribe to common topics
                    for topic in ["#", "$SYS/#", "home/#", "devices/#"]:
                        try:
                            self._mqtt_subscribe(ip, port, topic)
                            data["mqtt_topics"].append(topic)
                        except Exception:
                            break
            except Exception:
                pass

        if data["mqtt_broker_info"]:
            logger.info("MQTT scan %s: broker found on port %s", ip, ports)
        return data

    def _encode_remaining_length(self, length: int) -> bytes:
        result = bytearray()
        while True:
            byte = length % 128
            length = length >> 7
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)

    def _mqtt_subscribe(self, ip: str, port: int, topic: str):
        import struct
        packet_id = 1
        # SUBSCRIBE packet
        topic_bytes = topic.encode()
        var_header = struct.pack("!H", packet_id)
        payload = struct.pack("!H", len(topic_bytes)) + topic_bytes + b"\x00"  # QoS 0
        remaining = len(var_header) + len(payload)
        fixed_header = bytes([0x82]) + self._encode_remaining_length(remaining)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.sendall(fixed_header + var_header + payload)
        response = sock.recv(4096)
        sock.close()
        return response


# ── ONVIF Camera Scanner ──

class ONVIFScanner(BaseScanner):
    name = "onvif"
    description = "ONVIF: IP camera discovery via WS-Discovery, RTSP probe"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        open_ports = context.get("open_ports", [])
        camera_ports = [p for p in open_ports if p in [554, 80, 8080, 8443]]
        if not camera_ports:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_onvif_sync, ip)
        except Exception as e:
            logger.debug("ONVIF scan failed for %s: %s", ip, e)
            return {}

    def _scan_onvif_sync(self, ip: str) -> Dict[str, Any]:
        data = {}

        # WS-Discovery probe (UDP 3702)
        try:
            probe_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:wsd="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"'
                ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
                '<soap:Header>'
                '<wsd:MessageID>uuid:netmon-probe-' + str(os.getpid()) + '</wsd:MessageID>'
                '<wsd:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsd:To>'
                '<wsd:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe</wsd:Action>'
                '</soap:Header>'
                '<soap:Body>'
                '<wsd:Probe/>'
                '</soap:Body>'
                '</soap:Envelope>'
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(2)
            sock.sendto(probe_xml.encode(), (ip, 3702))
            resp, _ = sock.recvfrom(4096)
            sock.close()

            resp_text = resp.decode("utf-8", errors="ignore")
            if "onvif" in resp_text.lower() or "networkvideo" in resp_text.lower():
                data["onvif_detected"] = True
                # Extract scope info
                for tag in ["d:Types", "d:Scopes", "d:EndpointReference"]:
                    import re
                    match = re.search(f"<{tag}>(.*?)</{tag}>", resp_text)
                    if match:
                        data[f"onvif_{tag.split(':')[-1].lower()}"] = match.group(1)[:200]
        except Exception:
            pass

        # RTSP OPTIONS request on port 554
        if 554 in context.get("open_ports", []):
            try:
                options_req = (
                    "OPTIONS rtsp://" + ip + ":554/ RTSP/1.0\r\n"
                    "CSeq: 1\r\n"
                    "User-Agent: NetMon/1.0\r\n"
                    "\r\n"
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 554))
                sock.sendall(options_req.encode())
                resp = sock.recv(4096)
                sock.close()

                resp_text = resp.decode("utf-8", errors="ignore")
                if "RTSP/1.0" in resp_text or "Public:" in resp_text:
                    data["rtsp_available"] = True
                    for line in resp_text.split("\r\n"):
                        if line.lower().startswith("public:"):
                            data["rtsp_methods"] = line.split(":", 1)[-1].strip()
                        elif line.lower().startswith("server:"):
                            data["rtsp_server"] = line.split(":", 1)[-1].strip()
            except Exception:
                pass

        if data:
            logger.info("ONVIF scan %s: detected=%s", ip, data.get("onvif_detected"))
        return data


# ── IPP Printer Scanner ──

class IPPScanner(BaseScanner):
    name = "ipp"
    description = "IPP: printer discovery, status, toner levels, page counts"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        open_ports = context.get("open_ports", [])
        ipp_ports = [p for p in open_ports if p in [631, 9100]]
        if not ipp_ports:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_ipp_sync, ip, ipp_ports)
        except Exception as e:
            logger.debug("IPP scan failed for %s: %s", ip, e)
            return {}

    def _scan_ipp_sync(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        data = {}

        # HTTP GET to port 631 for printer status page
        if 631 in ports:
            try:
                result = subprocess.run(
                    ["curl", "-s", "-m", "3", "-k", f"http://{ip}:631/"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout:
                    html = result.stdout.lower()
                    if "printer" in html or "ipp" in html:
                        data["ipp_detected"] = True
                        # Try to extract printer info from HTML
                        import re
                        title_match = re.search(r"<title>(.*?)</title>", result.stdout, re.IGNORECASE)
                        if title_match:
                            data["printer_title"] = title_match.group(1).strip()[:100]
            except Exception:
                pass

        # SNMP walk of Printer-MIB
        try:
            for community in ["public", "private"]:
                # prtGeneralConfig
                result = subprocess.run(
                    ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", ip,
                     "1.3.6.1.2.1.25.3.5.1.1"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout and "No Such" not in result.stdout:
                    data["snmp_printer_detected"] = True
                    break

                # prtMarkerSupplies (toner levels)
                toner = subprocess.run(
                    ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", ip,
                     "1.3.6.1.2.1.43.11.1.1.8"],
                    capture_output=True, text=True, timeout=5,
                )
                if toner.stdout and "No Such" not in toner.stdout:
                    toner_vals = []
                    for line in toner.stdout.split("\n"):
                        if "=" in line:
                            val = line.split("=", 1)[1].strip()
                            try:
                                toner_vals.append(int(val))
                            except (ValueError, TypeError):
                                pass
                    if toner_vals:
                        data["toner_levels"] = toner_vals

                # prtMarkerLifeCount (pages printed)
                pages = subprocess.run(
                    ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", ip,
                     "1.3.6.1.2.1.43.10.2.1.4.1"],
                    capture_output=True, text=True, timeout=5,
                )
                if pages.stdout and "No Such" not in pages.stdout:
                    for line in pages.stdout.split("\n"):
                        if "=" in line:
                            val = line.split("=", 1)[1].strip()
                            try:
                                data["pages_printed"] = int(val)
                            except (ValueError, TypeError):
                                pass
                            break
        except Exception:
            pass

        # Try SNMP printer info via host-resources
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", "2c", "-c", "public", "-t", "2", ip,
                 "1.3.6.1.2.1.25.3.2.1.3"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout and "No Such" not in result.stdout:
                for line in result.stdout.split("\n"):
                    if "=" in line:
                        data.setdefault("printer_types", []).append(line.strip()[:100])
        except Exception:
            pass

        if data:
            logger.info("IPP scan %s: detected=%s", ip, data.get("ipp_detected"))
        return data


# ── Docker Scanner ──

class DockerScanner(BaseScanner):
    name = "docker"
    description = "Docker: container inventory, version, resource usage"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        os_info = context.get("os_guess", "")
        if any(kw in os_info.lower() for kw in ["windows", "microsoft"]):
            # Check via WMI for Docker Desktop service
            return self._scan_docker_wmi(ip)

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_docker_ssh, ip)
        except Exception as e:
            logger.debug("Docker scan failed for %s: %s", ip, e)
            return {}

    def _scan_docker_ssh(self, ip: str) -> Dict[str, Any]:
        data = {}
        # docker info
        info = self._ssh_cmd(ip, "docker info 2>/dev/null | head -20")
        if info:
            data["docker_detected"] = True
            for line in info.split("\n"):
                if "Server Version" in line:
                    data["docker_version"] = line.split(":", 1)[-1].strip()
                elif "Storage Driver" in line:
                    data["docker_storage"] = line.split(":", 1)[-1].strip()
                elif "Running" in line:
                    data["docker_running"] = line.split(":", 1)[-1].strip()
                elif "Paused" in line:
                    data["docker_paused"] = line.split(":", 1)[-1].strip()
                elif "Stopped" in line:
                    data["docker_stopped"] = line.split(":", 1)[-1].strip()

        # docker ps -a
        ps = self._ssh_cmd(ip, "docker ps -a --format '{{json .}}' 2>/dev/null | head -20")
        if ps:
            containers = []
            for line in ps.strip().split("\n"):
                if line.strip():
                    try:
                        c = json.loads(line.strip())
                        containers.append({
                            "id": c.get("ID", "")[:12],
                            "name": c.get("Names", ""),
                            "image": c.get("Image", ""),
                            "status": c.get("Status", ""),
                            "ports": c.get("Ports", ""),
                            "created": c.get("CreatedAt", ""),
                        })
                    except json.JSONDecodeError:
                        continue
            data["containers"] = containers

        if data.get("docker_detected"):
            logger.info("Docker scan %s: %s, %d containers",
                        ip, data.get("docker_version"), len(data.get("containers", [])))
        return data

    def _scan_docker_wmi(self, ip: str) -> Dict[str, Any]:
        data = {}
        try:
            result = subprocess.run(
                ["wmic", "/node:" + ip, "service", "get", "Name,State", "/format:list"],
                capture_output=True, text=True, timeout=8,
            )
            for line in result.stdout.splitlines():
                if "Docker" in line and "Running" in line:
                    data["docker_detected"] = True
                    data["docker_service"] = "Docker Desktop"
                    break
        except Exception:
            pass
        return data

    def _ssh_cmd(self, ip: str, cmd: str) -> str:
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                 "-o", "BatchMode=yes", f"root@{ip}", cmd],
                capture_output=True, text=True, timeout=8,
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""


# ── VM/Virtualization Scanner ──

class VMScanner(BaseScanner):
    name = "vm"
    description = "VM: virtualization detection — hypervisor type, VM name, UUID"

    # VMware MAC prefix: 00:50:56, VirtualBox: 08:00:27, Hyper-V: 00:15:5d
    VENDOR_MAC_PREFIXES = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "00:15:5d": "Hyper-V",
        "00:0c:29": "VMware",
        "00:05:69": "VMware",
        "00:1c:42": "Parallels",
    }

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_vm_sync, ip, context)
        except Exception as e:
            logger.debug("VM scan failed for %s: %s", ip, e)
            return {}

    def _scan_vm_sync(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        data = {}

        # Check MAC OUI prefix
        mac = context.get("mac", "")
        if mac:
            mac_prefix = ":".join(mac.split(":")[:3]).upper()
            for prefix, hypervisor in self.VENDOR_MAC_PREFIXES.items():
                if mac_prefix == prefix:
                    data["is_virtual"] = True
                    data["hypervisor_type"] = hypervisor
                    data["detection_method"] = "MAC OUI"
                    break

        os_info = context.get("os_guess", "")
        if any(kw in os_info.lower() for kw in ["vmware", "virtualbox", "hyper-v", "virtual"]):
            data["is_virtual"] = True
            data["hypervisor_type"] = os_info

        # WMI check on Windows
        if any(kw in os_info.lower() for kw in ["windows", "microsoft"]):
            try:
                result = subprocess.run(
                    ["wmic", "/node:" + ip, "csproduct", "get", "Name,Vendor,UUID", "/format:list"],
                    capture_output=True, text=True, timeout=8,
                )
                for line in result.stdout.splitlines():
                    if line.startswith("Name="):
                        name = line.split("=", 1)[1].strip()
                        data["vm_name"] = name
                        if any(v in name.lower() for v in ["vmware", "virtualbox", "virtual", "hyper-v"]):
                            data["is_virtual"] = True
                    elif line.startswith("Vendor="):
                        vendor = line.split("=", 1)[1].strip()
                        if vendor:
                            data["vm_vendor"] = vendor
                    elif line.startswith("UUID="):
                        data["vm_uuid"] = line.split("=", 1)[1].strip()
            except Exception:
                pass

        # Linux: systemd-detect-virt
        if any(kw in os_info.lower() for kw in ["linux", "unix", "ubuntu", "debian"]):
            try:
                # Try SSH
                result = subprocess.run(
                    ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                     "-o", "BatchMode=yes", f"root@{ip}", "systemd-detect-virt 2>/dev/null"],
                    capture_output=True, text=True, timeout=5,
                )
                virt_type = result.stdout.strip()
                if virt_type and virt_type != "none":
                    data["is_virtual"] = True
                    data["hypervisor_type"] = virt_type
                    data["detection_method"] = "systemd-detect-virt"
            except Exception:
                pass

        if data.get("is_virtual"):
            logger.info("VM scan %s: virtual=%s", ip, data.get("hypervisor_type"))
        return data


# ── Bandwidth Scanner (SNMP) ──

class BandwidthScanner(BaseScanner):
    name = "bandwidth"
    description = "Bandwidth: real-time traffic counters, utilization per interface"
    requires_nmap = True

    def _snmpwalk(self, ip: str, oid: str, community: str = "public") -> str:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v", "2c", "-c", community, "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except Exception:
            return ""

    def _parse_val(self, output: str) -> str:
        if "=" in output:
            val = output.split("=", 1)[1].strip()
            for prefix in ["STRING:", "OID:", "INTEGER:", "Gauge32:", "Counter32:", "Counter64:", "Timeticks:"]:
                if val.startswith(prefix):
                    val = val[len(prefix):].strip().strip('"')
            return val
        return ""

    def _find_community(self, ip: str) -> Optional[str]:
        for community in ["public", "private", "community"]:
            output = self._snmpwalk(ip, "1.3.6.1.2.1.1.1.0", community)
            if output and "No Such" not in output and "Timeout" not in output:
                return community
        return None

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_bw_sync, ip)
        except Exception as e:
            logger.debug("Bandwidth scan failed for %s: %s", ip, e)
            return {}

    def _scan_bw_sync(self, ip: str) -> Dict[str, Any]:
        community = self._find_community(ip)
        if not community:
            return {}

        data = {"interfaces": []}

        # Read counters at T1
        t1_counters = self._read_if_counters(ip, community)
        time.sleep(3)  # 3-second interval
        # Read counters at T2
        t2_counters = self._read_if_counters(ip, community)

        for iface_name in t1_counters:
            t1 = t1_counters[iface_name]
            t2 = t2_counters.get(iface_name, {})
            if not t2:
                continue

            try:
                delta_in = t2.get("in_octets", 0) - t1.get("in_octets", 0)
                delta_out = t2.get("out_octets", 0) - t1.get("out_octets", 0)
                interval = 3  # seconds

                bw_in = (delta_in * 8) / interval  # bits per second
                bw_out = (delta_out * 8) / interval

                speed = t1.get("speed_bps", 0)
                util_in = (bw_in / speed * 100) if speed > 0 else 0
                util_out = (bw_out / speed * 100) if speed > 0 else 0

                data["interfaces"].append({
                    "name": iface_name,
                    "bandwidth_in_bps": round(bw_in),
                    "bandwidth_out_bps": round(bw_out),
                    "utilization_in_pct": round(util_in, 2),
                    "utilization_out_pct": round(util_out, 2),
                    "speed_bps": speed,
                })
            except (ValueError, TypeError):
                pass

        if data["interfaces"]:
            logger.info("Bandwidth scan %s: %d interfaces", ip, len(data["interfaces"]))
        return data

    def _read_if_counters(self, ip: str, community: str) -> Dict[str, Dict]:
        ifaces = {}
        name_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.2", community)
        in_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.10", community)
        out_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.16", community)
        speed_output = self._snmpwalk(ip, "1.3.6.1.2.1.2.2.1.5", community)

        for line in name_output.split("\n"):
            if "ifDescr" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                ifaces.setdefault(idx, {})["name"] = self._parse_val(line)

        for line in in_output.split("\n"):
            if "ifInOctets" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["in_octets"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        for line in out_output.split("\n"):
            if "ifOutOctets" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["out_octets"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        for line in speed_output.split("\n"):
            if "ifSpeed" in line:
                idx = line.split(".")[1].split("=")[0].strip()
                try:
                    ifaces.setdefault(idx, {})["speed_bps"] = int(self._parse_val(line))
                except (ValueError, TypeError):
                    pass

        return {v.get("name", k): v for k, v in ifaces.items()}


# ── Bluetooth Scanner ──

class BluetoothScanner(BaseScanner):
    name = "bluetooth"
    description = "Bluetooth: nearby paired/discovered devices"

    async def scan_host(self, ip: str, context: Dict[str, Any]) -> Dict[str, Any]:
        # Bluetooth scanning only makes sense on local machine
        is_local = ip in ("127.0.0.1", "::1")
        if not is_local:
            return {}

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_bt_sync)
        except Exception as e:
            logger.debug("Bluetooth scan failed: %s", e)
            return {}

    def _scan_bt_sync(self) -> Dict[str, Any]:
        data = {"bt_devices": []}

        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-PnpDevice -Class Bluetooth | Select-Object -Property FriendlyName,Status,InstanceId | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    devices = json.loads(result.stdout)
                    if isinstance(devices, dict):
                        devices = [devices]
                    for dev in devices:
                        data["bt_devices"].append({
                            "name": dev.get("FriendlyName", ""),
                            "status": dev.get("Status", ""),
                            "instance_id": dev.get("InstanceId", ""),
                        })
            except Exception:
                pass

        elif platform.system() == "Linux":
            # bluetoothctl
            try:
                result = subprocess.run(
                    ["bluetoothctl", "devices"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.split("\n"):
                    if line.startswith("Device"):
                        parts = line.split(" ", 2)
                        if len(parts) >= 3:
                            data["bt_devices"].append({
                                "address": parts[1],
                                "name": parts[2],
                            })
            except Exception:
                pass

        if data["bt_devices"]:
            logger.info("Bluetooth scan: found %d devices", len(data["bt_devices"]))
        return data


# ── Scanner registry ──

SCANNER_MODULES: Dict[str, type] = {
    "snmp": SNMPScanner,
    "wmi": WMIScanner,
    "ssh": SSHScanner,
    "mdns": MDNSScanner,
    "upnp": UPnPScanner,
    "smb": SMBScanner,
    "http": HTTPProber,
    "nse": NmapNSEScanner,
    "registry": RegistryScanner,
    "lldp": LLDPScanner,
    "arp": ARPScanner,
    "dhcp": DHCPScanner,
    "vlan": VLANScanner,
    "traceroute": TracerouteScanner,
    "snmp_polling": SNMPPollingScanner,
    "vuln": VulnScanner,
    "ssl": SSLScanner,
    "mqtt": MQTTScanner,
    "onvif": ONVIFScanner,
    "ipp": IPPScanner,
    "docker": DockerScanner,
    "vm": VMScanner,
    "bandwidth": BandwidthScanner,
    "bluetooth": BluetoothScanner,
}

# Default enabled scanners
DEFAULT_ENABLED = ["nse", "http", "upnp", "snmp", "lldp", "arp", "dhcp", "ssl", "onvif", "ipp", "docker", "vm"]

# Module enabled states (mutable, persists in-memory across the session)
MODULE_ENABLED_STATE: Dict[str, bool] = {name: (name in DEFAULT_ENABLED) for name in SCANNER_MODULES}

def is_module_enabled(name: str) -> bool:
    if name in MODULE_ENABLED_STATE:
        return MODULE_ENABLED_STATE[name]
    return name in DEFAULT_ENABLED

def toggle_module(name: str) -> bool:
    if name not in SCANNER_MODULES:
        return False
    current = MODULE_ENABLED_STATE.get(name, name in DEFAULT_ENABLED)
    MODULE_ENABLED_STATE[name] = not current
    return MODULE_ENABLED_STATE[name]
