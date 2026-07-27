import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from database import (
    create_alert,
    get_all_devices,
    get_device_by_ip,
    get_ports_for_device,
    get_scan_history,
)

logger = logging.getLogger("netmon.alerts")

# ── Alert Rules Configuration ──

DEFAULT_RULES = {
    "new_device": {
        "enabled": True,
        "severity": "warning",
        "title_template": "Новое устройство: {ip}",
        "message_template": "Обнаружено новое устройство в сети. IP: {ip}, MAC: {mac}, Хост: {hostname}",
    },
    "device_offline": {
        "enabled": True,
        "severity": "critical",
        "title_template": "Устройство недоступно: {ip}",
        "message_template": "Устройство {ip} ({hostname}) не отвечает на запросы.",
    },
    "device_online": {
        "enabled": True,
        "severity": "info",
        "title_template": "Устройство вернулось в сеть: {ip}",
        "message_template": "Устройство {ip} ({hostname}) снова доступно.",
    },
    "port_opened": {
        "enabled": True,
        "severity": "warning",
        "title_template": "Открыт новый порт: {ip}:{port}",
        "message_template": "На устройстве {ip} открыт порт {port} ({service}).",
    },
    "port_closed": {
        "enabled": True,
        "severity": "info",
        "title_template": "Закрыт порт: {ip}:{port}",
        "message_template": "На устройстве {ip} закрыт порт {port} ({service}).",
    },
}


class AlertEngine:
    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = dict(DEFAULT_RULES)
        self._custom_rules: List[Callable] = []
        self._listeners: List[Callable] = []
        self._previous_ports: Dict[str, Set[int]] = {}
        self._previous_status: Dict[str, str] = {}

    def get_rules(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.rules)

    def set_rule(self, rule_name: str, enabled: bool) -> bool:
        if rule_name in self.rules:
            self.rules[rule_name]["enabled"] = enabled
            logger.info("Rule '%s' %s", rule_name, "enabled" if enabled else "disabled")
            return True
        return False

    def add_listener(self, callback: Callable):
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable):
        self._listeners = [l for l in self._listeners if l is not callback]

    def register_custom_rule(self, rule_fn: Callable):
        self._custom_rules.append(rule_fn)
        logger.info("Custom rule registered")

    async def _emit(self, alert_data: Dict[str, Any]):
        for listener in self._listeners:
            try:
                await listener("new_alert", alert_data)
            except Exception:
                logger.exception("Alert listener error")

    async def _fire_alert(
        self,
        rule_name: str,
        ip: str = "",
        mac: str = "",
        hostname: str = "",
        port: int = 0,
        service: str = "",
        details: Optional[Dict] = None,
    ) -> Optional[Dict[str, Any]]:
        rule = self.rules.get(rule_name)
        if not rule or not rule["enabled"]:
            return None

        title = rule["title_template"].format(
            ip=ip, mac=mac, hostname=hostname, port=port, service=service
        )
        message = rule["message_template"].format(
            ip=ip, mac=mac, hostname=hostname, port=port, service=service
        )

        alert = await create_alert(
            alert_type=rule_name,
            severity=rule["severity"],
            title=title,
            message=message,
            device_ip=ip,
            details=details,
        )

        logger.info("Alert fired: %s [%s] - %s", rule_name, rule["severity"], title)
        await self._emit(alert)
        return alert

    async def process_scan_results(self, scan_result: Dict[str, Any]) -> int:
        alerts_count = 0

        # Check new devices
        new_ips = scan_result.get("new_devices_list", [])
        for ip in new_ips:
            device = await get_device_by_ip(ip)
            if device:
                alert = await self._fire_alert(
                    "new_device",
                    ip=ip,
                    mac=device.get("mac", ""),
                    hostname=device.get("hostname", ""),
                    details={"device": device},
                )
                if alert:
                    alerts_count += 1

        # Check port changes
        devices = await get_all_devices()
        for device in devices:
            ip = device["ip"]
            ports = await get_ports_for_device(device["id"])
            current_port_numbers = {p["port"] for p in ports}
            previous = self._previous_ports.get(ip, set())

            # New ports opened
            opened = current_port_numbers - previous
            for port_num in opened:
                port_info = next((p for p in ports if p["port"] == port_num), {})
                alert = await self._fire_alert(
                    "port_opened",
                    ip=ip,
                    port=port_num,
                    service=port_info.get("service", ""),
                    details={"port": port_info},
                )
                if alert:
                    alerts_count += 1

            # Ports closed
            closed = previous - current_port_numbers
            for port_num in closed:
                alert = await self._fire_alert(
                    "port_closed",
                    ip=ip,
                    port=port_num,
                )
                if alert:
                    alerts_count += 1

            self._previous_ports[ip] = current_port_numbers

        return alerts_count

    async def check_device_status(
        self, ip: str, is_online: bool, device_info: Optional[Dict] = None
    ):
        previous = self._previous_status.get(ip)

        if is_online and previous == "offline":
            hostname = device_info.get("hostname", "") if device_info else ""
            await self._fire_alert(
                "device_online",
                ip=ip,
                hostname=hostname,
                details=device_info,
            )
        elif not is_online and previous == "online":
            hostname = device_info.get("hostname", "") if device_info else ""
            await self._fire_alert(
                "device_offline",
                ip=ip,
                hostname=hostname,
                details=device_info,
            )

        self._previous_status[ip] = "online" if is_online else "offline"

    async def run_custom_rules(self, context: Dict[str, Any]) -> int:
        count = 0
        for rule_fn in self._custom_rules:
            try:
                result = await rule_fn(context)
                if result:
                    count += 1
            except Exception:
                logger.exception("Custom rule error")
        return count


# Singleton
alert_engine = AlertEngine()
