import asyncio
import csv
import io
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from alerts import alert_engine
from database import (
    acknowledge_alert,
    assign_device_to_group,
    count_alerts_by_severity,
    create_group,
    delete_dashboard_config,
    delete_group,
    get_all_devices,
    get_alerts,
    get_dashboard_configs,
    get_device_with_ports,
    get_groups,
    get_ports_for_device,
    get_recent_snapshots,
    get_scan_history,
    init_db,
    save_dashboard_config,
    update_group,
)
from scanner import scanner
from classifier import get_classification_details, get_all_device_types
from scanners import SCANNER_MODULES, DEFAULT_ENABLED, BaseScanner, is_module_enabled, toggle_module
from wifi_scanner import scan_wifi_networks, get_wifi_interfaces

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netmon")

# ── WebSocket Manager ──

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("WebSocket connected (%d active)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info("WebSocket disconnected (%d active)", len(self.active_connections))

    async def broadcast(self, event_type: str, data: Any):
        message = json.dumps({"type": event_type, "data": data}, default=str)
        disconnected = set()
        for conn in self.active_connections:
            try:
                await conn.send_text(message)
            except Exception:
                disconnected.add(conn)
        for conn in disconnected:
            self.active_connections.discard(conn)


ws_manager = ConnectionManager()


# ── Scanner event handlers ──

async def on_scanner_event(event_type: str, data: Any):
    await ws_manager.broadcast(event_type, data)


# ── Alert event handlers ──

async def on_alert_event(event_type: str, data: Any):
    await ws_manager.broadcast(event_type, data)


# ── Lifespan ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    logger.info("Database initialized")

    scanner.add_listener(on_scanner_event)
    alert_engine.add_listener(on_alert_event)
    scanner.start()
    logger.info("Scanner started")

    yield

    # Shutdown
    scanner.stop()
    logger.info("Scanner stopped")


# ── App ──

app = FastAPI(
    title="NetMon — Network Monitor",
    description="Backend API for network monitoring tool",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic models ──

class DashboardConfigRequest(BaseModel):
    name: str
    config_json: str
    is_default: bool = False


class ScannerConfigRequest(BaseModel):
    interval: Optional[int] = None
    subnet: Optional[str] = None


class AlertRuleRequest(BaseModel):
    enabled: bool


class AlertAcknowledgeResponse(BaseModel):
    success: bool
    message: str


class GroupRequest(BaseModel):
    name: str
    parent_id: Optional[int] = None
    description: str = ""


class GroupUpdateRequest(BaseModel):
    name: Optional[str] = None
    parent_id: Optional[int] = None
    description: Optional[str] = None


class AssignGroupRequest(BaseModel):
    group_id: Optional[int] = None


# ── Device type detection ──

def guess_device_type(device: dict, ports: list) -> str:
    from classifier import classify_device
    return classify_device(
        ip=device.get("ip", ""),
        ports=ports,
        os_info=device.get("os_guess"),
        hostname=device.get("hostname"),
        vendor=device.get("vendor"),
        gateway_ip=scanner._gateway_ip,
    )

    os_info = (device.get("os_guess") or "").lower()
    if any(kw in os_info for kw in ["windows", "microsoft"]):
        return "pc"
    if any(kw in os_info for kw in ["linux", "unix", "ubuntu", "debian", "centos"]):
        return "server"
    if any(kw in os_info for kw in ["android", "ios", "iphone", "samsung"]):
        return "phone"

    return "pc"


def detect_sensors(device: dict, ports: list) -> dict:
    port_numbers = {p["port"] for p in ports}
    services = [p.get("service", "") for p in ports if p.get("service")]

    sensor_indicators = []
    if 1883 in port_numbers or 8883 in port_numbers:
        sensor_indicators.append("MQTT")
    if 5683 in port_numbers:
        sensor_indicators.append("CoAP")
    if 9100 in port_numbers:
        sensor_indicators.append("Принтер/Датчик")
    if 11211 in port_numbers:
        sensor_indicators.append("Кэш (Memcached)")
    if 2181 in port_numbers:
        sensor_indicators.append("ZooKeeper")
    if 9090 in port_numbers:
        sensor_indicators.append("Prometheus")
    if 18080 in port_numbers:
        sensor_indicators.append("IBM Watson IoT")
    if 5222 in port_numbers or 5228 in port_numbers:
        sensor_indicators.append("XMPP/Push")

    total_sensors = len(sensor_indicators)
    if not sensor_indicators and len(port_numbers) >= 4:
        total_sensors = len(port_numbers)
        sensor_indicators = [f"Порт {p}" for p in sorted(port_numbers)]

    return {
        "is_sensor_device": total_sensors >= 2,
        "sensor_count": total_sensors,
        "sensor_types": sensor_indicators,
    }


# ── Device endpoints ──

@app.get("/api/devices")
async def list_devices():
    devices = await get_all_devices()
    for dev in devices:
        ports = await get_ports_for_device(dev["id"])
        dev["ports"] = ports
        dev["type"] = guess_device_type(dev, ports)
        dev["sensors"] = detect_sensors(dev, ports)
    return {"devices": devices, "total": len(devices)}


@app.get("/api/devices/{ip}")
async def get_device(ip: str):
    device = await get_device_with_ports(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    device["type"] = guess_device_type(device, device.get("ports", []))
    device["sensors"] = detect_sensors(device, device.get("ports", []))
    return {"device": device}


@app.get("/api/devices/{ip}/classify")
async def classify_device_endpoint(ip: str):
    device = await get_device_with_ports(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    details = get_classification_details(
        ip=ip,
        ports=device.get("ports", []),
        os_info=device.get("os_guess"),
        hostname=device.get("hostname"),
        vendor=device.get("vendor"),
        gateway_ip=scanner._gateway_ip,
    )
    return details


@app.get("/api/device-types")
async def list_device_types():
    return {"types": get_all_device_types()}


@app.get("/api/devices/{ip}/antivirus")
async def get_antivirus_info(ip: str):
    device = await get_device_with_ports(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    from classifier import detect_antivirus
    hw = json.loads(device.get("hardware_json") or "{}")
    av = detect_antivirus(hardware=hw, os_info=device.get("os_guess"))
    return {"ip": ip, "antivirus": av}


# ── Alert endpoints ──

@app.get("/api/alerts")
async def list_alerts(
    alert_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    alerts = await get_alerts(
        alert_type=alert_type,
        severity=severity,
        acknowledged=acknowledged,
        limit=limit,
        offset=offset,
    )
    severity_counts = await count_alerts_by_severity()
    return {
        "alerts": alerts,
        "total": len(alerts),
        "severity_counts": severity_counts,
    }


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert_endpoint(alert_id: int):
    success = await acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(
            status_code=404,
            detail="Оповещение не найдено или уже подтверждено",
        )
    return {"success": True, "message": "Оповещение подтверждено"}


@app.get("/api/alerts/rules")
async def list_alert_rules():
    rules = alert_engine.get_rules()
    return {"rules": rules}


@app.put("/api/alerts/rules/{rule_name}")
async def update_alert_rule(rule_name: str, request: AlertRuleRequest):
    success = alert_engine.set_rule(rule_name, request.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    return {"success": True, "message": f"Правило '{rule_name}' {'включено' if request.enabled else 'выключено'}"}


# ── Scan endpoints ──

@app.get("/api/scan/status")
async def scan_status():
    status = scanner.status
    return {
        "running": status.running,
        "scan_type": status.scan_type,
        "started_at": status.started_at,
        "progress": status.progress,
        "total": status.total,
        "devices_found": status.devices_found,
        "new_devices": status.new_devices,
        "last_scan_at": status.last_scan_at,
        "error": status.error,
    }


@app.post("/api/scan/trigger")
async def trigger_scan():
    if scanner.status.running:
        return {"message": "Сканирование уже выполняется", "status": "already_running"}

    async def run_and_notify():
        result = await scanner.run_scan(scan_type="manual")
        await alert_engine.process_scan_results(result)

    asyncio.create_task(run_and_notify())
    return {"message": "Сканирование запущено", "status": "started"}


@app.get("/api/scan/history")
async def scan_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    history = await get_scan_history(limit=limit, offset=offset)
    return {"history": history, "total": len(history)}


# ── Dashboard endpoints ──

@app.get("/api/dashboard/configs")
async def list_dashboard_configs():
    configs = await get_dashboard_configs()
    return {"configs": configs}


@app.post("/api/dashboard/configs")
async def save_dashboard_config_endpoint(request: DashboardConfigRequest):
    config = await save_dashboard_config(
        name=request.name,
        config_json=request.config_json,
        is_default=request.is_default,
    )
    return {"config": config, "message": "Конфигурация сохранена"}


@app.delete("/api/dashboard/configs/{config_id}")
async def delete_dashboard_config_endpoint(config_id: int):
    success = await delete_dashboard_config(config_id)
    if not success:
        raise HTTPException(status_code=404, detail="Конфигурация не найдена")
    return {"success": True, "message": "Конфигурация удалена"}


# ── Stats endpoint ──

@app.get("/api/stats")
async def get_stats():
    devices = await get_all_devices()
    online = sum(1 for d in devices if d["status"] == "online")
    offline = sum(1 for d in devices if d["status"] == "offline")
    severity_counts = await count_alerts_by_severity()

    return {
        "total_devices": len(devices),
        "online": online,
        "offline": offline,
        "alerts": severity_counts,
        "scan_running": scanner.status.running,
        "last_scan": scanner.status.last_scan_at,
    }


# ── Scanner config endpoints ──

@app.get("/api/scanner/config")
async def get_scanner_config():
    return {
        "interval": scanner.scan_interval,
        "subnet": scanner.subnet or scanner._subnet,
        "subnets": scanner._detected_subnets,
        "scan_type": scanner.status.scan_type or "auto",
    }


@app.put("/api/scanner/config")
async def update_scanner_config(request: ScannerConfigRequest):
    if request.interval is not None:
        if request.interval < 10 or request.interval > 86400:
            raise HTTPException(status_code=400, detail="Интервал должен быть от 10 до 86400 секунд")
        scanner.scan_interval = request.interval

    if request.subnet is not None:
        scanner.subnet = request.subnet

    return {
        "interval": scanner.scan_interval,
        "subnet": scanner.subnet,
        "message": "Настройки сканера обновлены",
    }


# ── Scanner modules management ──

@app.get("/api/scanner/modules")
async def list_scanner_modules():
    modules = []
    for name, cls in SCANNER_MODULES.items():
        instance = cls()
        modules.append({
            "name": name,
            "description": instance.description,
            "enabled": is_module_enabled(name),
            "requires_root": instance.requires_root,
            "requires_nmap": instance.requires_nmap,
        })
    return {"modules": modules}


@app.put("/api/scanner/modules/{module_name}/toggle")
async def toggle_scanner_module(module_name: str):
    if module_name not in SCANNER_MODULES:
        raise HTTPException(status_code=404, detail=f"Модуль '{module_name}' не найден")
    new_state = toggle_module(module_name)
    return {
        "module": module_name,
        "enabled": new_state,
        "message": f"Модуль '{module_name}' {'включён' if new_state else 'выключен'}",
    }


# ── WiFi endpoints ──

@app.get("/api/wifi/scan")
async def wifi_scan():
    """Scan for available WiFi networks."""
    networks = scan_wifi_networks()
    return {"networks": networks, "total": len(networks)}


@app.get("/api/wifi/interfaces")
async def wifi_interfaces():
    """Get WiFi interface information."""
    interfaces = get_wifi_interfaces()
    return {"interfaces": interfaces, "total": len(interfaces)}


# ── Export endpoints ──

@app.get("/api/export/devices")
async def export_devices_csv():
    devices = await get_all_devices()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "MAC", "Hostname", "OS", "Vendor", "Status", "First Seen", "Last Seen"])

    for dev in devices:
        writer.writerow([
            dev.get("ip", ""),
            dev.get("mac", ""),
            dev.get("hostname", ""),
            dev.get("os_guess", ""),
            dev.get("vendor", ""),
            dev.get("status", ""),
            dev.get("first_seen", ""),
            dev.get("last_seen", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netmon-devices.csv"},
    )


# ── Reports endpoints ──

@app.get("/api/reports/devices")
async def report_devices():
    devices = await get_all_devices()
    report = []
    for dev in devices:
        ports = await get_ports_for_device(dev["id"])
        report.append({
            "id": dev["id"],
            "ip": dev["ip"],
            "mac": dev["mac"] or "",
            "hostname": dev["hostname"] or "",
            "os": dev["os_guess"] or "",
            "vendor": dev["vendor"] or "",
            "subnet": dev["subnet"] or "",
            "status": dev["status"],
            "type": guess_device_type(dev, ports),
            "hardware": json.loads(dev.get("hardware_json") or "{}"),
            "ports_count": len(ports),
            "group_id": dev.get("group_id"),
            "first_seen": dev["first_seen"],
            "last_seen": dev["last_seen"],
        })
    return {"devices": report, "total": len(report)}


@app.get("/api/reports/devices/csv")
async def report_devices_csv():
    devices = await get_all_devices()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP", "MAC", "Hostname", "OS", "Vendor", "Subnet", "Status",
        "Type", "CPU", "RAM (GB)", "Disk (GB)", "Uptime (h)",
        "Ports", "First Seen", "Last Seen",
    ])

    for dev in devices:
        hw = json.loads(dev.get("hardware_json") or "{}")
        ports = await get_ports_for_device(dev["id"])
        writer.writerow([
            dev.get("ip", ""),
            dev.get("mac", ""),
            dev.get("hostname", ""),
            dev.get("os_guess", ""),
            dev.get("vendor", ""),
            dev.get("subnet", ""),
            dev.get("status", ""),
            guess_device_type(dev, ports),
            hw.get("cpu_model", ""),
            hw.get("ram_total_gb", ""),
            hw.get("disk_total_gb", ""),
            hw.get("uptime_hours", ""),
            len(ports),
            dev.get("first_seen", ""),
            dev.get("last_seen", ""),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netmon-inventory.csv"},
    )


@app.get("/api/reports/changes")
async def report_changes(limit: int = Query(50, ge=1, le=500)):
    snapshots = await get_recent_snapshots(limit=limit)
    changes = []
    for snap in snapshots:
        snap_data = json.loads(snap.get("snapshot_json") or "{}")
        changes.append({
            "device_id": snap.get("device_id"),
            "ip": snap.get("ip"),
            "hostname": snap.get("hostname"),
            "type": snap.get("type"),
            "snapshot": snap_data,
            "created_at": snap.get("created_at"),
        })
    return {"changes": changes, "total": len(changes)}


# ── Groups endpoints ──

@app.get("/api/groups")
async def list_groups():
    groups = await get_groups()
    return {"groups": groups, "total": len(groups)}


@app.post("/api/groups")
async def create_group_endpoint(request: GroupRequest):
    group = await create_group(
        name=request.name,
        parent_id=request.parent_id,
        description=request.description,
    )
    return {"group": group, "message": "Группа создана"}


@app.put("/api/groups/{group_id}")
async def update_group_endpoint(group_id: int, request: GroupUpdateRequest):
    success = await update_group(
        group_id=group_id,
        name=request.name,
        parent_id=request.parent_id,
        description=request.description,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Группа не найдена")
    return {"success": True, "message": "Группа обновлена"}


@app.delete("/api/groups/{group_id}")
async def delete_group_endpoint(group_id: int):
    success = await delete_group(group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Группа не найдена")
    return {"success": True, "message": "Группа удалена"}


@app.put("/api/devices/{device_id}/group")
async def assign_device_group(device_id: int, request: AssignGroupRequest):
    success = await assign_device_to_group(device_id, request.group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    return {"success": True, "message": "Устройство назначено в группу"}


# ── WebSocket ──

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ── Static files ──

frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
