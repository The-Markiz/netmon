# NetMon — Техническая документация

---

## Архитектура системы

```
┌─────────────────────────────────────────────────┐
│                  Frontend (React)                │
│  App.jsx → Sidebar → NetworkMap / DeviceList /  │
│  DeviceTree / AlertDashboard / Reports /        │
│  WiFiScan / Settings                            │
└──────────────────────┬──────────────────────────┘
                       │ REST API + WebSocket
┌──────────────────────┴──────────────────────────┐
│                  Backend (FastAPI)                │
│  main.py → scanner.py → scanners.py (24 модуля) │
│         → classifier.py → database.py           │
│         → alerts.py → wifi_scanner.py            │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────┐
│              SQLite Database                     │
│  devices / ports / alerts / scan_history /       │
│  dashboard_configs / device_groups /             │
│  device_snapshots                               │
└─────────────────────────────────────────────────┘
```

---

## Модули сканеров — детальное описание

### Архитектура модулей

Каждый модуль наследуется от `BaseScanner`:

```python
class BaseScanner:
    name: str           # Имя модуля
    description: str    # Описание
    requires_root: bool # Нужны права root
    requires_nmap: bool # Нужен nmap
    enabled: bool       # Включён ли

    async def scan_host(self, ip: str, context: dict) -> dict:
        """Сканирование одного хоста. Возвращает обогащённые данные."""
        return {}
```

Модули регистрируются в `SCANNER_MODULES` dict и вызываются последовательно для каждого хоста при сканировании.

### Процесс сканирования

```
run_scan()
  ├── _detect_all_subnets()     # Найти все подсети
  ├── Для каждой подсети:
  │   ├── _discover_hosts()     # nmap -sn или scapy ARP
  │   └── Для каждого хоста:
  │       ├── _get_os_info()    # nmap -O или ICMP TTL
  │       ├── _scan_ports()     # nmap -sS или scapy SYN
  │       ├── classify_device() # Многофакторная классификация
  │       ├── _scan_hardware()  # WMI/SSH hardware inventory
  │       ├── Scanner Modules:  # Все включённые модули
  │       │   ├── SNMP → интерфейсы, LLDP, CDP
  │       │   ├── WMI → CPU, RAM, диск, ПО, антивирус
  │       │   ├── SSH → система, пакеты, Docker
  │       │   ├── SSL → сертификаты
  │       │   ├── HTTP → fingerprint
  │       │   ├── UPnP → SSDP
  │       │   ├── ARP → таблица связей
  │       │   ├── DHCP → аренды
  │       │   ├── ONVIF → IP-камеры
  │       │   ├── IPP → принтеры
  │       │   ├── Docker → контейнеры
  │       │   ├── VM → виртуализация
  │       │   └── ... (24 модуля)
  │       ├── _detect_changes() # Сравнение с предыдущим снимком
  │       └── save_snapshot()   # Сохранить снимок
  └── mark_offline()            # Пометить неактивные
```

---

## Классификация устройств

### Факторы голосования

| Фактор | Вес | Пример |
|--------|-----|--------|
| Gateway IP match | +50 | IP совпадает с шлюзом → router |
| Порты (SNMP) | +8 | Порт 161 → switch/router |
| Порты (сервисные) | +10 | 3+ портов 80/443/3306 → server |
| Порты (IoT) | +8 | MQTT 1883, CoAP 5683 → iot |
| ОС (сетевая) | +15 | OpenWrt, MikroTik → router |
| ОС (FW) | +15 | FortiOS, pfSense → ngfw |
| ОС (Linux) | +8 | Ubuntu, Debian → server |
| ОС (Windows) | +8 | Windows → pc |
| Hostname | +5-8 | "srv" → server, "fw" → firewall |
| Vendor | +6 | Cisco → router, Kaspersky → ngfw |
| Hardware RAM | +5 | ≥16ГБ → server |
| Hardware CPU | +3 | ≥8 ядер → server |
| Кол-во портов 0 | +1 | → iot |
| Кол-во портов 10+ | +3 | → server |

### Типы устройств

router, switch, firewall, ngfw, ids, wap, server, pc, laptop, phone, printer, camera, media, nas, iot, scada, ups, scanner

---

## Обнаружение антивируса

### Методы обнаружения

1. **Windows (WMI services)** — проверка имён процессов:
   - MsMpEng → Windows Defender
   - csfalconservice → CrowdStrike Falcon
   - avp.exe → Kaspersky
   - 30+ сигнатур

2. **Windows (WMI software)** — проверка установленного ПО через `wmic product`

3. **Linux (SSH)** — проверка бинарников:
   - clamscan → ClamAV
   - ossec/wazuh → HIDS
   - snort/suricata → IDS

4. **Общее** — паттерны в названиях ПО:
   - "kaspersky" → Kaspersky
   - "crowdstrike" → CrowdStrike Falcon
   - 20+ паттернов

---

## База данных

### Таблицы

| Таблица | Описание |
|---------|----------|
| `devices` | Устройства: ip, mac, hostname, os_guess, vendor, subnet, type, hardware_json, group_id |
| `ports` | Порты: device_id, port, protocol, state, service, version |
| `alerts` | Алерты: type, severity, title, message, device_ip, acknowledged |
| `scan_history` | История сканирований |
| `dashboard_configs` | Конфигурации дашборда |
| `device_groups` | Группы устройств (иерархия через parent_id) |
| `device_snapshots` | Снимки hardware для отслеживания изменений |

### Hardware JSON

Структура `hardware_json` в таблице `devices`:

```json
{
  "cpu_model": "Intel Core i7-12700",
  "cpu_cores": 12,
  "ram_total_gb": 32.0,
  "ram_used_gb": 18.5,
  "disk_total_gb": 500.0,
  "disk_used_gb": 210.0,
  "os_name": "Windows 11",
  "os_version": "23H2",
  "uptime_hours": 144,
  "open_ports_count": 15,
  "antivirus": [
    {"name": "CrowdStrike Falcon", "vendor": "CrowdStrike", "source": "service"}
  ],
  "scanner_snmp": {
    "snmp_sysdescr": "...",
    "snmp_interfaces": [...],
    "snmp_neighbors": [...]
  },
  "scanner_wmi": {
    "wmi_cpu": "...",
    "wmi_network_adapters": "..."
  },
  "scanner_ssl": {
    "cert_issuer": "Let's Encrypt",
    "cert_days_remaining": 45
  },
  "scanner_docker": {
    "docker_version": "24.0.7",
    "containers": [...]
  },
  "scanner_vm": {
    "is_virtual": true,
    "hypervisor_type": "VMware"
  }
}
```

---

## WiFi сканирование

### Реализация по платформам

| Платформа | Инструмент | Данные |
|-----------|-----------|--------|
| Windows | `netsh wlan show networks mode=bssid` | SSID, BSSID, Signal, Channel, Radio, Security |
| Linux | `nmcli -t dev wifi list` | SSID, Signal, Channel, Security, BSSID |
| Linux (fallback) | `iwlist wlan0 scanning` | SSID, Signal (dBm), Channel, Encryption |
| macOS | `airport -s` | SSID, BSSID, RSSI, Channel, Security |

### Конвертация сигнала

```
dBm → %: signal_percent = 2 × (dBm + 100)
% → качество:
  ≥ -50 dBm → Отличный (зелёный)
  ≥ -60 dBm → Хороший (лайм)
  ≥ -70 dBm → Средний (янтарь)
  ≥ -80 dBm → Слабый (оранжевый)
  < -80 dBm → Очень слабый (красный)
```

---

## Классификация Антивируса

### Windows (процессы)

| Процесс | Продукт | Вендор |
|---------|---------|--------|
| MsMpEng | Windows Defender | Microsoft |
| csfalconservice | CrowdStrike Falcon | CrowdStrike |
| avp.exe | Kaspersky | Kaspersky |
| ccSvcHst | Norton Security | Norton |
| mcshield | McAfee | McAfee |
| bdagent | Bitdefender | Bitdefender |
| ekrn | ESET NOD32 | ESET |
| SentinelAgent | SentinelOne | SentinelOne |
| CylanceSvc | Cylance | BlackBerry |
| TaniumClient | Tanium | Tanium |

### Linux (бинарники)

| Бинарник | Продукт |
|----------|---------|
| clamscan | ClamAV |
| rkhunter | Rootkit Hunter |
| ossec | OSSEC HIDS |
| wazuh | Wazuh |
| snort | Snort IDS |
| suricata | Suricata IDS |
| lynis | Lynis (аудит) |

### Общие паттерны (по названию ПО)

Kaspersky, Norton, McAfee, Bitdefender, ESET, Avira, Sophos, SentinelOne, CrowdStrike, Trend Micro, F-Secure, Malwarebytes, Avast, AVG, Webroot, Panda, Comodo, ZoneAlarm, Symantec

---

## Типы устройств — детали

| Тип | Цвет | Иконка | Описание |
|-----|------|--------|----------|
| router | #f59e0b | Router (◇) | Маршрутизатор |
| switch | #8b5cf6 | Zap | Коммутатор L2/L3 |
| firewall | #ef4444 | Shield | FW: фильтрация, NAT |
| ngfw | #dc2626 | ShieldAlert | Next-Gen FW + IPS/IDS + контроль приложений |
| ids | #b91c1c | ShieldCheck | IDS/IPS: анализ трафика |
| wap | #22d3ee | Wifi | WiFi точка доступа |
| server | #3b82f6 | Server | Сервер (физ/виртуал) |
| pc | #10b981 | Monitor | Рабочая станция |
| laptop | #34d399 | MonitorSmartphone | Ноутбук |
| phone | #06b6d4 | Smartphone | Телефон |
| printer | #a855f7 | Printer | Принтер/МФУ |
| camera | #f97316 | Camera | IP-камера |
| media | #14b8a6 | Radio | Медиа-устройство |
| nas | #6366f1 | HardDrive | Сетевое хранилище |
| iot | #ec4899 | Cpu | Умный дом |
| scada | #78350f | Cpu | Промышленный контроллер |
| ups | #059669 | Zap | ИБП |

---

## Конфигурация

### Переменные окружения

| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|----------|
| `NETMON_SCAN_INTERVAL` | `30` | Интервал фонового сканирования (сек) |
| `NETMON_SCAN_TYPE` | `auto` | Движок: `auto` / `nmap` / `scapy` |
| `NETMON_SUBNET` | (авто) | Подсеть (CIDR). Если не задана — авто-определение |
| `ARP_FILE` | (нет) | Путь к ARP JSON файлу (Docker) |

### Настройки через UI

**Сканер:**
- Интервал сканирования (10–86400 сек)
- Подсеть (CIDR или авто)
- 24 модуля сканеров — включение/выключение

**Алерты:**
- 5 правил: new_device, device_offline, device_online, port_opened, port_closed
- Каждое правило: severity, title_template, message_template

**Дашборд:**
- Виджеты: статистика, алерты, устройства, сканирование
- Порядок виджетов, включение/выключение

---

## Запуск

### Docker
```bash
cd netmon
docker compose up --build -d
# http://localhost:8000
```

### Без Docker
```bash
cd netmon/backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Windows скрипт
```bat
cd netmon
start.bat
```

---

## Требования

| Компонент | Минимум | Рекомендуется |
|-----------|---------|---------------|
| Python | 3.10+ | 3.12+ |
| Node.js | 18+ | 20+ |
| nmap | - | 7.80+ |
| net-snmp | - | SNMP сканеры |
| sshpass | - | SSH сканирование |
| ОС | Windows/Linux/macOS | |
| RAM | 512MB | 2GB+ |
| Диск | 100MB | 1GB+ |
