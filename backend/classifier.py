"""
Device type classification engine.
Multi-factor scoring system based on nmap/LibreNMS heuristics + extended SOC types.

Signals used:
  1. SNMP sysObjectID / sysDescr (most reliable)
  2. Nmap OS fingerprint (-O)
  3. Open ports + service detection
  4. MAC OUI vendor prefix
  5. Hostname patterns
  6. Hardware info (CPU, RAM)
  7. Network position (gateway = router)
  8. Running services / installed software
  9. Antivirus / security product detection
"""
from typing import Any, Dict, List, Optional

# ── All supported device types with descriptions ──
DEVICE_TYPE_INFO = {
    "router":       {"label": "Маршрутизатор", "color": "#f59e0b", "icon": "Router",
                     "desc": "Маршрутизатор — устройство, соединяющее несколько сетей. Перенаправляет пакеты между подсетями."},
    "switch":       {"label": "Коммутатор", "color": "#8b5cf6", "icon": "Zap",
                     "desc": "Коммутатор L2/L3 — расширение сети с избирательной маршрутизацией пакетов."},
    "firewall":     {"label": "Межсетевой экран", "color": "#ef4444", "icon": "Shield",
                     "desc": "FW — контролирует трафик, фильтрует по правилам, NAT, port forwarding."},
    "ngfw":         {"label": "NGFW", "color": "#dc2626", "icon": "ShieldAlert",
                     "desc": "Next-Gen Firewall — FW + IPS/IDS + контроль приложений + SSL inspection."},
    "ids":          {"label": "IDS/IPS", "color": "#b91c1c", "icon": "ShieldCheck",
                     "desc": "Система обнаружения/предотвращения вторжений. Анализ трафика на аномалии."},
    "wap":          {"label": "Точка доступа WiFi", "color": "#22d3ee", "icon": "Wifi",
                     "desc": "Беспроводная точка доступа (802.11). Обеспечивает WiFi-подключение."},
    "server":       {"label": "Сервер", "color": "#3b82f6", "icon": "Server",
                     "desc": "Физический или виртуальный сервер. Предоставляет сервисы (web, DB, файлы)."},
    "pc":           {"label": "Рабочая станция", "color": "#10b981", "icon": "Monitor",
                     "desc": "Настольный ПК или ноутбук. Рабочее место пользователя."},
    "laptop":       {"label": "Ноутбук", "color": "#34d399", "icon": "MonitorSmartphone",
                     "desc": "Портативное устройство. Отличается от PC мобильностью."},
    "phone":        {"label": "Телефон", "color": "#06b6d4", "icon": "Smartphone",
                     "desc": "Мобильный телефон или VoIP-телефон."},
    "printer":      {"label": "Принтер", "color": "#a855f7", "icon": "Printer",
                     "desc": "Сетевой принтер/МФУ с встроенным сервером печати."},
    "camera":       {"label": "Камера", "color": "#f97316", "icon": "Camera",
                     "desc": "IP-камера наблюдения (NVR/DVR). Часто IoT-устройство."},
    "media":        {"label": "Медиа-устройство", "color": "#14b8a6", "icon": "Radio",
                     "desc": "Медиаплеер, smart TV, ресивер, аудиосистема."},
    "nas":          {"label": "Сетевое хранилище", "color": "#6366f1", "icon": "HardDrive",
                     "desc": "NAS — сетевое хранилище данных (Synology, QNAP, FreeNAS)."},
    "iot":          {"label": "IoT / Умный дом", "color": "#ec4899", "icon": "Cpu",
                     "desc": "Умная колонка, датчик, реле, контроллер, ESP8266/ESP32."},
    "scada":        {"label": "SCADA / Промышленный контроллер", "color": "#78350f", "icon": "Cpu",
                     "desc": "Промышленный контроллер (PLC, RTU, HMI). Критическая инфраструктура."},
    "ups":          {"label": "ИБП (UPS)", "color": "#059669", "icon": "Zap",
                     "desc": "Источник бесперебойного питания. Мониторинг через SNMP."},
    "scanner":      {"label": "Сканер / 3D-принтер", "color": "#7c3aed", "icon": "Printer",
                     "desc": "3D-принтер, сканер документов или другой peripherals."},
}

# ── Port signatures ──
PORT_SIGNATURES: Dict[int, Dict[str, int]] = {
    # Network infrastructure
    22:    {"server": 3, "pc": 2, "switch": 1},
    23:    {"switch": 4, "server": 2, "router": 2},
    53:    {"router": 5, "server": 2},
    80:    {"server": 4, "router": 3, "switch": 2, "printer": 2, "iot": 2},
    443:   {"server": 4, "router": 3, "switch": 2, "printer": 2, "iot": 2},
    161:   {"switch": 8, "router": 8, "firewall": 6, "printer": 4, "nas": 4},
    162:   {"switch": 6, "router": 6},
    520:   {"router": 6},
    1900:  {"switch": 4, "router": 3, "printer": 3, "iot": 3},
    62078: {"phone": 8},
    8291:  {"switch": 6, "router": 6},
    8728:  {"switch": 5, "router": 5},
    8080:  {"server": 3, "router": 2, "iot": 2, "printer": 2},
    8443:  {"server": 3, "router": 2},
    # Services
    21:    {"server": 3, "nas": 4},
    25:    {"server": 4},
    110:   {"server": 3},
    143:   {"server": 3},
    445:   {"server": 3, "pc": 2},
    993:   {"server": 3},
    995:   {"server": 3},
    1433:  {"server": 5},
    3306:  {"server": 5},
    3389:  {"pc": 5, "server": 3},
    5432:  {"server": 5},
    5900:  {"pc": 4, "server": 3},
    6379:  {"server": 4},
    27017: {"server": 4},
    # IoT / special
    1883:  {"iot": 8},
    8883:  {"iot": 7},
    5683:  {"iot": 7},
    9100:  {"printer": 8, "iot": 3},
    5222:  {"iot": 5, "phone": 3},
    11211: {"server": 4, "iot": 3},
    9090:  {"server": 3, "iot": 3},
    # Media
    1935:  {"media": 6},
    554:   {"media": 5},
    4000:  {"media": 4},
    7000:  {"media": 4},
    # NAS
    5000:  {"nas": 5},
    5001:  {"nas": 5},
    8081:  {"nas": 3},
    139:   {"nas": 4, "pc": 3},
    # Security / FW
    8443:  {"ngfw": 4, "firewall": 3},
    4100:  {"ids": 6},
    10000: {"ngfw": 5, "firewall": 4},
    4434:  {"ids": 5},
}

# ── Hostname patterns ──
HOSTNAME_PATTERNS: Dict[str, Dict[str, int]] = {
    "router": {"router": 8}, "gw": {"router": 7}, "gateway": {"router": 7}, "rt": {"router": 5},
    "fw": {"firewall": 7}, "firewall": {"firewall": 7}, "ngfw": {"ngfw": 8},
    "ids": {"ids": 8}, "ips": {"ids": 7},
    "sw": {"switch": 7}, "switch": {"switch": 7}, "swp": {"switch": 6},
    "srv": {"server": 7}, "server": {"server": 7}, "db": {"server": 6},
    "mail": {"server": 6}, "web": {"server": 5}, "dns": {"server": 5},
    "ldap": {"server": 5}, "sql": {"server": 5},
    "pc": {"pc": 7}, "ws": {"pc": 5}, "workstation": {"pc": 7},
    "laptop": {"laptop": 8}, "nb": {"laptop": 5},
    "printer": {"printer": 8}, "print": {"printer": 6}, "hp": {"printer": 3},
    "cam": {"camera": 6}, "camera": {"camera": 6}, "nvr": {"camera": 6}, "dvr": {"camera": 6},
    "iot": {"iot": 8}, "sensor": {"iot": 7}, "hub": {"iot": 5},
    "alexa": {"iot": 7}, "echo": {"iot": 7}, "smart": {"iot": 4},
    "nas": {"nas": 8}, "synology": {"nas": 8}, "qnap": {"nas": 8}, "diskstation": {"nas": 8},
    "ups": {"ups": 8}, "apc": {"ups": 6},
    "phone": {"phone": 8}, "iphone": {"phone": 8}, "android": {"phone": 7}, "sip": {"phone": 5},
    "plc": {"scada": 8}, "rtu": {"scada": 8}, "hmi": {"scada": 7}, "scada": {"scada": 8},
    "switch": {"switch": 7},
}

# ── Vendor → type mapping ──
VENDOR_TYPE_HINTS: Dict[str, str] = {
    "Cisco": "router", "MikroTik": "switch", "Ubiquiti": "switch",
    "TP-Link": "switch", "D-Link": "switch", "Netgear": "switch",
    "Juniper": "router", "Arista": "switch", "HPE": "switch",
    "Fortinet": "ngfw", "Palo Alto": "ngfw", "Sophos": "ngfw",
    "WatchGuard": "ngfw", "Check Point": "ngfw", "SonicWall": "ngfw",
    "Untangle": "ngfw", "pfSense": "firewall", "OPNsense": "firewall",
    "Meraki": "wap",
    "Brother": "printer", "Epson": "printer", "Canon": "printer",
    "Xerox": "printer", "Lexmark": "printer", "Ricoh": "printer",
    "Kyocera": "printer", "Sharp": "printer", "HP": "printer",
    "Ring": "camera", "Nest": "iot", "Wyze": "camera", "Hikvision": "camera", "Dahua": "camera",
    "Sonos": "media", "Roku": "media", "Chromecast": "media",
    "Apple TV": "media", "Fire TV": "media",
    "Synology": "nas", "QNAP": "nas", "Western Digital": "nas", "Netgear ReadyNAS": "nas",
    "APC": "ups", "Eaton": "ups", "CyberPower": "ups",
    "Allen-Bradley": "scada", "Siemens": "scada", "Schneider": "scada",
    "VMware": "server", "VirtualBox": "server", "QEMU": "server", "Parallels": "server",
    "Dell": "server", "Supermicro": "server",
    "Apple": "phone", "Samsung": "phone", "OnePlus": "phone",
    "Xiaomi": "iot", "Huawei": "phone", "Google": "iot",
    "Crestron": "scada", "Extron": "media",
}

# ── Antivirus detection signatures ──
AV_SIGNATURES = {
    # Windows AV by service/process names
    "windows": [
        {"process": "MsMpEng", "name": "Windows Defender", "vendor": "Microsoft"},
        {"process": "ccSvcHst", "name": "Norton Security", "vendor": "Norton"},
        {"process": "mcshield", "name": "McAfee", "vendor": "McAfee"},
        {"process": "avp.exe", "name": "Kaspersky", "vendor": "Kaspersky"},
        {"process": "bdagent", "name": "Bitdefender", "vendor": "Bitdefender"},
        {"process": "ekrn", "name": "ESET NOD32", "vendor": "ESET"},
        {"process": "avguard", "name": "Avira", "vendor": "Avira"},
        {"process": "avgsvc", "name": "AVG", "vendor": "AVG"},
        {"process": "savservice", "name": "Sophos", "vendor": "Sophos"},
        {"process": "SentinelAgent", "name": "SentinelOne", "vendor": "SentinelOne"},
        {"process": "CBDefense", "name": "Carbon Black", "vendor": "Carbon Black"},
        {"process": "CylanceSvc", "name": "Cylance", "vendor": "BlackBerry Cylance"},
        {"process": "TaniumClient", "name": "Tanium", "vendor": "Tanium"},
        {"process": "csfalconservice", "name": "CrowdStrike Falcon", "vendor": "CrowdStrike"},
        {"process": "wrsvc", "name": "Webroot", "vendor": "Webroot"},
        {"process": "PSUAService", "name": "Panda Security", "vendor": "Panda"},
        {"process": "vnserv", "name": "VirusBulletin", "vendor": "VirusBulletin"},
    ],
    # Linux AV by package/binary names
    "linux": [
        {"binary": "clamscan", "name": "ClamAV", "vendor": "ClamAV"},
        {"binary": "rkhunter", "name": "Rootkit Hunter", "vendor": "Rootkit Hunter"},
        {"binary": "chkrootkit", "name": "chkrootkit", "vendor": "chkrootkit"},
        {"binary": "lynis", "name": "Lynis (audit)", "vendor": "CISOfy"},
        {"binary": "aide", "name": "AIDE (IDS)", "vendor": "AIDE"},
        {"binary": "ossec", "name": "OSSEC HIDS", "vendor": "OSSEC"},
        {"binary": "wazuh", "name": "Wazuh", "vendor": "Wazuh"},
        {"binary": "tripwire", "name": "Tripwire", "vendor": "Tripwire"},
        {"binary": "snort", "name": "Snort (IDS)", "vendor": "Snort"},
        {"binary": "suricata", "name": "Suricata (IDS)", "vendor": "Suricata"},
    ],
}

# Antivirus by WMI product names
AV_PRODUCT_PATTERNS = {
    "microsoft defender": "Windows Defender",
    "microsoft security essentials": "Windows Defender",
    "norton": "Norton Security",
    "mcafee": "McAfee",
    "kaspersky": "Kaspersky",
    "bitdefender": "Bitdefender",
    "eset": "ESET NOD32",
    "nod32": "ESET NOD32",
    "avira": "Avira",
    "avg": "AVG",
    "avast": "Avast",
    "sophos": "Sophos",
    "sentinelone": "SentinelOne",
    "carbon black": "Carbon Black",
    "cylance": "Cylance",
    "crowdstrike": "CrowdStrike Falcon",
    "tanium": "Tanium",
    "webroot": "Webroot",
    "panda": "Panda Security",
    "f-secure": "F-Secure",
    "trend micro": "Trend Micro",
    "symantec": "Symantec Endpoint",
    "comodo": "Comodo",
    "zonealarm": "ZoneAlarm",
    "malwarebytes": "Malwarebytes",
}


def classify_device(
    ip: str,
    ports: List[Dict[str, Any]],
    os_info: Optional[str] = None,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    gateway_ip: Optional[str] = None,
    hardware: Optional[Dict[str, Any]] = None,
) -> str:
    """Multi-factor device type classification. Returns device type string."""
    result = get_classification_details(ip, ports, os_info, hostname, vendor, gateway_ip, hardware)
    return result["type"]


def get_classification_details(
    ip: str,
    ports: List[Dict[str, Any]],
    os_info: Optional[str] = None,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    gateway_ip: Optional[str] = None,
    hardware: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Returns detailed classification with scores, reasons, and security info."""
    all_types = list(DEVICE_TYPE_INFO.keys())
    scores: Dict[str, float] = {t: 0.0 for t in all_types}
    reasons = []

    port_numbers = {p["port"] for p in ports}

    # ── Factor 1: Gateway ──
    if gateway_ip and ip == gateway_ip:
        scores["router"] += 50
        reasons.append("IP совпадает с шлюзом → router")

    # ── Factor 2: Port signatures ──
    for port in port_numbers:
        if port in PORT_SIGNATURES:
            for dev_type, weight in PORT_SIGNATURES[port].items():
                if dev_type in scores:
                    scores[dev_type] += weight

    service_ports = port_numbers & {80, 443, 8080, 8443, 3306, 5432, 1433, 6379, 27017}
    if len(service_ports) >= 3:
        scores["server"] += 10
        reasons.append(f"{len(service_ports)} сервисных портов → server")

    iot_ports = port_numbers & {1883, 8883, 5683, 9100, 5222, 11211, 9090}
    if len(iot_ports) >= 2:
        scores["iot"] += 8
        reasons.append(f"{len(iot_ports)} IoT-портов → iot")

    nas_ports = port_numbers & {5000, 5001, 139, 8081}
    if len(nas_ports) >= 2:
        scores["nas"] += 6
        reasons.append(f"NAS-порты → nas")

    # ── Factor 3: OS fingerprint ──
    if os_info:
        os_lower = os_info.lower()
        if any(kw in os_lower for kw in ["cisco ios", "cisco ios-xe", "cisco ios-xr", "juniper", "mikrotik", "openwrt", "dd-wrt", "vyos"]):
            scores["router"] += 15
            scores["switch"] += 10
            reasons.append(f"Сетевая ОС '{os_info}' → router/switch")
        if any(kw in os_lower for kw in ["fortios", "pfsense", "opnsense", "palo alto", "check point", "sophos", "sonicwall", "untangle"]):
            scores["ngfw"] += 15
            scores["firewall"] += 10
            reasons.append(f"FW ОС → ngfw/firewall")
        if any(kw in os_lower for kw in ["snort", "suricata", "ossec", "wazuh", "security onion"]):
            scores["ids"] += 15
            reasons.append(f"IDS/IPS ОС → ids")
        if any(kw in os_lower for kw in ["printer", "laserjet", "inkjet", "plc-xu", "hp laserjet"]):
            scores["printer"] += 15
        if any(kw in os_lower for kw in ["linux", "ubuntu", "debian", "centos", "red hat", "freebsd", "vmware esxi", "proxmox"]):
            scores["server"] += 8
        if any(kw in os_lower for kw in ["windows", "microsoft", "windows server"]):
            scores["pc"] += 8
            if "server" in os_lower:
                scores["server"] += 5
        if any(kw in os_lower for kw in ["android", "ios", "iphone"]):
            scores["phone"] += 12
        if any(kw in os_lower for kw in ["android tv", "roku", "chromecast", "sonos"]):
            scores["media"] += 12

    # ── Factor 4: Hostname patterns ──
    if hostname:
        hostname_lower = hostname.lower()
        for pattern, type_scores in HOSTNAME_PATTERNS.items():
            if pattern in hostname_lower:
                for dev_type, weight in type_scores.items():
                    if dev_type in scores:
                        scores[dev_type] += weight
                reasons.append(f"Hostname содержит '{pattern}'")

    # ── Factor 5: Vendor hints ──
    if vendor:
        for vendor_pattern, dev_type in VENDOR_TYPE_HINTS.items():
            if vendor_pattern.lower() in vendor.lower():
                if dev_type in scores:
                    scores[dev_type] += 6
                reasons.append(f"Vendor '{vendor}' → {dev_type}")
                break

    # ── Factor 6: Hardware hints ──
    if hardware:
        ram = hardware.get("ram_total_gb", 0)
        cores = hardware.get("cpu_cores", 0)
        if ram and ram >= 16 and cores and cores >= 4:
            scores["server"] += 5
        if ram and ram <= 1:
            scores["iot"] += 3
        if cores and cores >= 8:
            scores["server"] += 3

    # ── Factor 7: Port count heuristics ──
    num_ports = len(port_numbers)
    if num_ports == 0:
        scores["iot"] += 1
    elif num_ports >= 10:
        scores["server"] += 3
        scores["iot"] += 2

    # ── Antivirus detection ──
    antivirus_found = detect_antivirus(hardware, os_info)

    # ── Determine winner ──
    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    if best_score < 3:
        best_type = "unknown"

    type_info = DEVICE_TYPE_INFO.get(best_type, DEVICE_TYPE_INFO.get("pc", {}))

    return {
        "type": best_type,
        "score": best_score,
        "scores": {k: v for k, v in sorted(scores.items(), key=lambda x: -x[1]) if v > 0},
        "reasons": reasons,
        "type_label": type_info.get("label", best_type),
        "type_desc": type_info.get("desc", ""),
        "antivirus": antivirus_found,
    }


def detect_antivirus(hardware: Optional[Dict[str, Any]] = None, os_info: Optional[str] = None) -> List[Dict[str, str]]:
    """Detect installed antivirus/security products from available data."""
    found = []
    os_lower = (os_info or "").lower()

    # Check WMI software list
    if hardware:
        for key, value in hardware.items():
            if not value or not isinstance(value, str):
                continue
            value_lower = value.lower()
            for pattern, av_name in AV_PRODUCT_PATTERNS.items():
                if pattern in value_lower:
                    found.append({"name": av_name, "source": "installed_software"})
                    break

        # Check WMI services for AV processes
        for key, value in hardware.items():
            if not value or not isinstance(value, str):
                continue
            for sig_list in AV_SIGNATURES.values():
                for sig in sig_list:
                    process = sig.get("process", "")
                    if process and process.lower() in value.lower():
                        found.append({"name": sig["name"], "vendor": sig.get("vendor", ""), "source": "service"})

        # Check running processes
        if "wmi_services" in hardware and isinstance(hardware["wmi_services"], str):
            for sig in AV_SIGNATURES.get("windows", []):
                if sig.get("process", "").lower() in hardware["wmi_services"].lower():
                    if not any(av["name"] == sig["name"] for av in found):
                        found.append({"name": sig["name"], "vendor": sig.get("vendor", ""), "source": "service"})

        # Check Linux processes
        for key, value in hardware.items():
            if not value or not isinstance(value, str):
                continue
            for sig in AV_SIGNATURES.get("linux", []):
                if sig.get("binary", "").lower() in value.lower():
                    if not any(av["name"] == sig["name"] for av in found):
                        found.append({"name": sig["name"], "vendor": sig.get("vendor", ""), "source": "binary"})

    return found


def get_all_device_types() -> List[Dict[str, str]]:
    """Returns all available device types with metadata."""
    return [
        {"key": k, "label": v["label"], "color": v["color"], "desc": v["desc"]}
        for k, v in DEVICE_TYPE_INFO.items()
    ]
