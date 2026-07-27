# NetMon — Мониторинг сети

Инструмент для автоматического обнаружения, классификации и мониторинга сетевых устройств. Разработан для SOC-команд, нуждающихся в полной видимости сетевой инфраструктуры.

---

## Возможности

### Обнаружение устройств
- **Автоматическое определение подсетей** — находит все локальные сети (WiFi, VMware, Ethernet) и сканирует каждую
- **Хост-дискавери** — nmap (ICMP/ARP) или scapy (ARP broadcast)
- **Классификация устройств** — многофакторная система: порты, ОС, MAC OUI, hostname, железо
- **24 типа устройств** — маршрутизатор, NGFW, IDS/IPS, коммутатор, сервер, ПК, ноутбук, телефон, принтер, камера, медиа, NAS, IoT, SCADA, UPS и др.

### Сканирование и сбор данных
- **Порты** — TCP SYN/connect сканирование (top-20 портов)
- **Определение ОС** — nmap -O (TCP fingerprint) или ICMP TTL
- **Hardware inventory** — CPU, RAM, диск, uptime (WMI для Windows, SSH для Linux)
- **Обнаружение антивируса** — 30+ продуктов (Defender, Kaspersky, CrowdStrike, ESET и др.)
- **WiFi** — сканирование доступных сетей (SSID, BSSID, сигнал, канал, безопасность)

### 24 модуля сканеров (включаются/выключаются в настройках)

| Модуль | Описание | По умолчанию |
|--------|----------|:---:|
| **nmap** | NSE: определение ОС, сервисов, уязвимостей | Вкл |
| **snmp** | sysDescr, sysName, интерфейсы, LLDP/CDP соседи | Вкл |
| **http** | fingerprint сервисов, HTTP title, статус-коды | Вкл |
| **upnp** | UPnP/SSDP: smart home, медиа-устройства | Вкл |
| **lldp** | LLDP/CDP: физическая топология через SNMP | Вкл |
| **arp** | ARP-таблица: IP→MAC маппинг | Вкл |
| **dhcp** | DHCP-аренды: IP, MAC, hostname, срок аренды | Вкл |
| **ssl** | SSL/TLS: сертификаты, сроки, протоколы, шифры | Вкл |
| **onvif** | IP-камеры: WS-Discovery, RTSP | Вкл |
| **ipp** | Принтеры: статус, уровень тонера, счётчик страниц | Вкл |
| **docker** | Docker: версия, контейнеры, ресурсы | Вкл |
| **vm** | Виртуализация: тип гипервизора, имя VM | Вкл |
| **wmi** | Windows: CPU, RAM, диск, ПО, антивирус, сетевые адаптеры | Выкл |
| **ssh** | Linux: система, пакеты, процессы, Docker | Выкл |
| **smb** | Windows: домен, шары, NetBIOS | Выкл |
| **mdns** | mDNS/Bonjour: Apple, IoT, принтеры | Выкл |
| **registry** | Windows Registry: ПО, конфигурация | Выкл |
| **vuln** | Nmap NSE vuln: CVE, уязвимости | Выкл |
| **snmp_polling** | CPU/RAM/диск/трафик в реальном времени | Выкл |
| **bandwidth** | Трафик интерфейсов: bps, утилизация | Выкл |
| **vlan** | VLAN membership через SNMP | Выкл |
| **traceroute** | Маршрут до хоста, задержки по хопам | Выкл |
| **mqtt** | MQTT брокер: темы, клиенты | Выкл |
| **bluetooth** | Bluetooth: сопряжённые/обнаруженные устройства | Выкл |

### Мониторинг
- **Авто-сканирование** по расписанию (интервал настраивается)
- **Обнаружение изменений** — сравнение hardware-снимков между сканированиями
- **Алерты** — new_device, device_offline, port_opened/closed, device_changed
- **WebSocket** — обновления в реальном времени

### Управление
- **Дерево сети** — иерархическая группировка устройств
- **Отчёты** — JSON/CSV инвентаризация с железом
- **WiFi** — таблица доступных сетей с уровнем сигнала
- **Карта сети** — визуальная топология с классификацией устройств

---

## Быстрый старт

### Запуск (Docker)
```bash
cd netmon
docker compose up --build -d
# Интерфейс: http://localhost:8000
```

### Запуск (без Docker)
```bash
cd netmon/backend
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# В другом терминале (для dev-режима фронтенда):
cd netmon/frontend
npm install && npm run dev
```

### Запуск (скрипт)
```bash
# Windows
start.bat

# Linux/Mac
chmod +x start.sh && ./start.sh
```

---

## Структура проекта

```
netmon/
├── backend/
│   ├── main.py              # FastAPI: эндпоинты, WebSocket, статика
│   ├── scanner.py           # Основной сканер: хост-дискавери, полное сканирование
│   ├── scanners.py          # 24 модуля сканеров
│   ├── classifier.py        # Классификация устройств (18 типов)
│   ├── database.py          # SQLite: устройства, порты, алерты, снимки
│   ├── alerts.py            # Движок алертов
│   ├── wifi_scanner.py      # Сканирование WiFi сетей
│   ├── start.py             # Точка входа для запуска
│   ├── data/
│   │   └── oui.py           # База OUI-вендоров (MAC → производитель)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Роутинг
│   │   ├── components/
│   │   │   ├── Sidebar.jsx         # Навигация
│   │   │   ├── StatsBar.jsx        # Строка статистики
│   │   │   ├── NetworkMap.jsx      # Карта сети + панель устройства
│   │   │   ├── DeviceList.jsx      # Таблица устройств
│   │   │   ├── DeviceTree.jsx      # Дерево сети
│   │   │   ├── AlertDashboard.jsx  # Алерты
│   │   │   ├── Reports.jsx         # Отчёты
│   │   │   ├── WiFiScan.jsx        # WiFi сканирование
│   │   │   └── Settings.jsx        # Настройки
│   │   └── styles/main.css
│   └── package.json
├── docker-compose.yml
├── Dockerfile
├── start.bat / start.sh
└── README.md
```

---

## API

### Устройства
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/devices` | Список всех устройств |
| GET | `/api/devices/{ip}` | Детали устройства |
| GET | `/api/devices/{ip}/classify` | Детали классификации |
| GET | `/api/devices/{ip}/antivirus` | Обнаруженные антивирусы |
| PUT | `/api/devices/{id}/group` | Назначить группу |

### Сканеры
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/scanner/modules` | Список 24 модулей |
| PUT | `/api/scanner/modules/{name}/toggle` | Вкл/выкл модуль |
| GET | `/api/scanner/config` | Конфигурация сканера |
| PUT | `/api/scanner/config` | Обновить настройки |
| POST | `/api/scan/trigger` | Запустить сканирование |
| GET | `/api/scan/status` | Статус сканирования |

### WiFi
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/wifi/scan` | Сканирование WiFi сетей |
| GET | `/api/wifi/interfaces` | WiFi интерфейсы |

### Алерты
| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/alerts` | Список алертов |
| POST | `/api/alerts/{id}/acknowledge` | Подтвердить алерт |
| GET | `/api/alerts/rules` | Правила алертов |
| PUT | `/api/alerts/rules/{name}` | Вкл/выкл правило |

### Группы и отчёты
| Метод | Путь | Описание |
|-------|------|----------|
| GET/POST | `/api/groups` | Управление группами |
| PUT/DELETE | `/api/groups/{id}` | Изменить/удалить группу |
| GET | `/api/reports/devices` | JSON отчёт |
| GET | `/api/reports/devices/csv` | CSV экспорт |
| GET | `/api/device-types` | Все типы устройств |

### WebSocket
| Путь | Описание |
|------|----------|
| `/ws/events` | new_device, device_offline, scan_progress, scan_completed, device_changed |

---

## Классификация устройств

Многофакторная система голосования с 9 факторами:

1. **Gateway** — IP совпадает с шлюзом → router (+50)
2. **Порты** — каждому порту сопоставлены веса для каждого типа
3. **ОС** — nmap -O fingerprint: OpenWrt → router, Windows → pc, Linux → server
4. **Hostname** — паттерны: "srv" → server, "fw" → firewall, "iot" → iot
5. **Vendor** — OUI база: Cisco → router, Kaspersky → ngfw
6. **Hardware** — RAM ≥16ГБ + CPU ≥4 ядра → server
7. **Количество портов** — 0 → IoT, ≥10 → server
8. **Антивирус** — обнаруженные продукты безопасности
9. **Сервисные порты** — 80/443/8080 → server, 1883 → IoT

---

## Системные требования

### Backend
- Python 3.10+
- nmap (опционально, для расширенного сканирования)
- root/sudo (для ARP и raw socket сканирования)

### Frontend
- Node.js 18+

### Опционально
- net-snmp (snmpwalk/snmpget) — для SNMP сканеров
- sshpass — для SSH сканирования с паролем
- openssl — для SSL сертификатов

---

## Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `NETMON_SCAN_INTERVAL` | `30` | Интервал фонового сканирования (сек) |
| `NETMON_SCAN_TYPE` | `auto` | Тип: `auto` / `nmap` / `scapy` |
| `NETMON_SUBNET` | (авто) | Подсеть для сканирования (CIDR) |
| `ARP_FILE` | (нет) | Путь к ARP файлу (Docker режим) |
