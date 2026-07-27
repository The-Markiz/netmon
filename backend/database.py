import aiosqlite
import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "netmon.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    os_guess TEXT,
    vendor TEXT,
    subnet TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'online',
    extra_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT,
    service TEXT,
    version TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    device_ip TEXT,
    details_json TEXT,
    created_at TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    devices_found INTEGER DEFAULT 0,
    new_devices INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dashboard_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    config_json TEXT NOT NULL,
    is_default INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    parent_id INTEGER,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_ports_device_id ON ports(device_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_device_groups_parent ON device_groups(parent_id);
CREATE INDEX IF NOT EXISTS idx_device_snapshots_device ON device_snapshots(device_id);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        # Migration: add subnet column if missing
        try:
            await db.execute("ALTER TABLE devices ADD COLUMN subnet TEXT")
            await db.commit()
        except Exception:
            pass  # Column already exists
        # Migration: add group_id column if missing
        try:
            await db.execute("ALTER TABLE devices ADD COLUMN group_id INTEGER")
            await db.commit()
        except Exception:
            pass
        # Migration: add hardware_json column if missing
        try:
            await db.execute("ALTER TABLE devices ADD COLUMN hardware_json TEXT DEFAULT '{}'")
            await db.commit()
        except Exception:
            pass


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Device CRUD ──

async def upsert_device(
    ip: str,
    mac: Optional[str] = None,
    hostname: Optional[str] = None,
    os_guess: Optional[str] = None,
    vendor: Optional[str] = None,
    subnet: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    db = await get_db()
    try:
        existing = await db.execute_fetchall(
            "SELECT * FROM devices WHERE ip = ?", (ip,)
        )
        if existing:
            row = dict(existing[0])
            new_status = "online"
            fields: List[str] = ["last_seen = ?", "status = ?"]
            values: List[Any] = [now_iso(), new_status]
            if mac:
                fields.append("mac = ?")
                values.append(mac)
            if hostname:
                fields.append("hostname = ?")
                values.append(hostname)
            if os_guess:
                fields.append("os_guess = ?")
                values.append(os_guess)
            if vendor:
                fields.append("vendor = ?")
                values.append(vendor)
            if subnet:
                fields.append("subnet = ?")
                values.append(subnet)
            values.append(ip)
            await db.execute(
                f"UPDATE devices SET {', '.join(fields)} WHERE ip = ?", values
            )
            await db.commit()
            updated = await db.execute_fetchall(
                "SELECT * FROM devices WHERE ip = ?", (ip,)
            )
            return dict(updated[0])
        else:
            ts = now_iso()
            cur = await db.execute(
                """INSERT INTO devices (ip, mac, hostname, os_guess, vendor, subnet,
                   first_seen, last_seen, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online')""",
                (ip, mac, hostname, os_guess, vendor, subnet, ts, ts),
            )
            await db.commit()
            row = await db.execute_fetchall(
                "SELECT * FROM devices WHERE id = ?", (cur.lastrowid,)
            )
            return dict(row[0]) if row else None
    finally:
        await db.close()


async def mark_device_offline(ip: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE devices SET status = 'offline' WHERE ip = ?", (ip,)
        )
        await db.commit()
    finally:
        await db.close()


async def get_device_by_ip(ip: str) -> Optional[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM devices WHERE ip = ?", (ip,)
        )
        if rows:
            return dict(rows[0])
        return None
    finally:
        await db.close()


async def get_device_by_id(device_id: int) -> Optional[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        )
        return dict(rows[0]) if rows else None
    finally:
        await db.close()


async def get_all_devices() -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT * FROM devices ORDER BY last_seen DESC")
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_devices_with_ports() -> List[Dict[str, Any]]:
    devices = await get_all_devices()
    db = await get_db()
    try:
        for dev in devices:
            port_rows = await db.execute_fetchall(
                "SELECT * FROM ports WHERE device_id = ?", (dev["id"],)
            )
            dev["ports"] = [dict(p) for p in port_rows]
        return devices
    finally:
        await db.close()


async def get_device_with_ports(ip: str) -> Optional[Dict[str, Any]]:
    device = await get_device_by_ip(ip)
    if not device:
        return None
    db = await get_db()
    try:
        port_rows = await db.execute_fetchall(
            "SELECT * FROM ports WHERE device_id = ?", (device["id"],)
        )
        device["ports"] = [dict(p) for p in port_rows]
        return device
    finally:
        await db.close()


# ── Port CRUD ──

async def set_ports(device_id: int, ports_list: List[Dict[str, Any]]):
    db = await get_db()
    try:
        await db.execute("DELETE FROM ports WHERE device_id = ?", (device_id,))
        for p in ports_list:
            await db.execute(
                """INSERT INTO ports (device_id, port, protocol, state, service, version)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    device_id,
                    p["port"],
                    p.get("protocol", "tcp"),
                    p.get("state", "open"),
                    p.get("service", ""),
                    p.get("version", ""),
                ),
            )
        await db.commit()
    finally:
        await db.close()


async def get_ports_for_device(device_id: int) -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM ports WHERE device_id = ?", (device_id,)
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


# ── Alert CRUD ──

async def create_alert(
    alert_type: str,
    severity: str,
    title: str,
    message: str = "",
    device_ip: str = "",
    details: Optional[Dict] = None,
) -> Dict[str, Any]:
    db = await get_db()
    try:
        ts = now_iso()
        details_json = json.dumps(details or {}, ensure_ascii=False)
        cur = await db.execute(
            """INSERT INTO alerts (alert_type, severity, title, message,
               device_ip, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (alert_type, severity, title, message, device_ip, details_json, ts),
        )
        await db.commit()
        row = await db.execute_fetchall(
            "SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)
        )
        return dict(row[0]) if row else {}
    finally:
        await db.close()


async def get_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        conditions: List[str] = []
        params: List[Any] = []
        if alert_type:
            conditions.append("alert_type = ?")
            params.append(alert_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            conditions.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = await db.execute_fetchall(query, params)
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def acknowledge_alert(alert_id: int) -> bool:
    db = await get_db()
    try:
        cur = await db.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ? AND acknowledged = 0",
            (alert_id,),
        )
        await db.commit()
        return cur.rowcount > 0
    finally:
        await db.close()


async def count_alerts_by_severity() -> Dict[str, int]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT severity, COUNT(*) as cnt FROM alerts WHERE acknowledged = 0 GROUP BY severity"
        )
        return {r["severity"]: r["cnt"] for r in rows}
    finally:
        await db.close()


# ── Scan History ──

async def create_scan_record(scan_type: str) -> int:
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO scan_history (scan_type, started_at) VALUES (?, ?)",
            (scan_type, now_iso()),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


async def finish_scan_record(
    scan_id: int,
    devices_found: int = 0,
    new_devices: int = 0,
    alerts_generated: int = 0,
):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE scan_history SET finished_at = ?, devices_found = ?,
               new_devices = ?, alerts_generated = ? WHERE id = ?""",
            (now_iso(), devices_found, new_devices, alerts_generated, scan_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_scan_history(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


# ── Dashboard Configs ──

async def get_dashboard_configs() -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM dashboard_configs ORDER BY is_default DESC, name"
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def save_dashboard_config(name: str, config_json: str, is_default: bool = False) -> Dict[str, Any]:
    db = await get_db()
    try:
        existing = await db.execute_fetchall(
            "SELECT id FROM dashboard_configs WHERE name = ?", (name,)
        )
        if existing:
            await db.execute(
                "UPDATE dashboard_configs SET config_json = ?, is_default = ? WHERE name = ?",
                (config_json, 1 if is_default else 0, name),
            )
            await db.commit()
            row = await db.execute_fetchall(
                "SELECT * FROM dashboard_configs WHERE name = ?", (name,)
            )
        else:
            cur = await db.execute(
                "INSERT INTO dashboard_configs (name, config_json, is_default) VALUES (?, ?, ?)",
                (name, config_json, 1 if is_default else 0),
            )
            await db.commit()
            row = await db.execute_fetchall(
                "SELECT * FROM dashboard_configs WHERE id = ?", (cur.lastrowid,)
            )
        return dict(row[0]) if row else {}
    finally:
        await db.close()


async def delete_dashboard_config(config_id: int) -> bool:
    db = await get_db()
    try:
        cur = await db.execute(
            "DELETE FROM dashboard_configs WHERE id = ?", (config_id,)
        )
        await db.commit()
        return cur.rowcount > 0
    finally:
        await db.close()


# ── Device Groups ──

async def get_groups() -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM device_groups ORDER BY name"
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def create_group(name: str, parent_id: Optional[int] = None, description: str = "") -> Dict[str, Any]:
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO device_groups (name, parent_id, description, created_at) VALUES (?, ?, ?, ?)",
            (name, parent_id, description, now_iso()),
        )
        await db.commit()
        row = await db.execute_fetchall(
            "SELECT * FROM device_groups WHERE id = ?", (cur.lastrowid,)
        )
        return dict(row[0]) if row else {}
    finally:
        await db.close()


async def update_group(group_id: int, name: Optional[str] = None, parent_id: Optional[int] = None, description: Optional[str] = None) -> bool:
    db = await get_db()
    try:
        fields: List[str] = []
        values: List[Any] = []
        if name is not None:
            fields.append("name = ?")
            values.append(name)
        if parent_id is not None:
            fields.append("parent_id = ?")
            values.append(parent_id)
        if description is not None:
            fields.append("description = ?")
            values.append(description)
        if not fields:
            return False
        values.append(group_id)
        cur = await db.execute(
            f"UPDATE device_groups SET {', '.join(fields)} WHERE id = ?", values
        )
        await db.commit()
        return cur.rowcount > 0
    finally:
        await db.close()


async def delete_group(group_id: int) -> bool:
    db = await get_db()
    try:
        # Unassign devices from this group
        await db.execute(
            "UPDATE devices SET group_id = NULL WHERE group_id = ?", (group_id,)
        )
        cur = await db.execute(
            "DELETE FROM device_groups WHERE id = ?", (group_id,)
        )
        await db.commit()
        return cur.rowcount > 0
    finally:
        await db.close()


async def assign_device_to_group(device_id: int, group_id: Optional[int]) -> bool:
    db = await get_db()
    try:
        cur = await db.execute(
            "UPDATE devices SET group_id = ? WHERE id = ?", (group_id, device_id)
        )
        await db.commit()
        return cur.rowcount > 0
    finally:
        await db.close()


# ── Device Snapshots / Change Detection ──

async def save_device_snapshot(device_id: int, snapshot_json: str) -> Dict[str, Any]:
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO device_snapshots (device_id, snapshot_json, created_at) VALUES (?, ?, ?)",
            (device_id, snapshot_json, now_iso()),
        )
        await db.commit()
        row = await db.execute_fetchall(
            "SELECT * FROM device_snapshots WHERE id = ?", (cur.lastrowid,)
        )
        return dict(row[0]) if row else {}
    finally:
        await db.close()


async def get_latest_snapshot(device_id: int) -> Optional[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM device_snapshots WHERE device_id = ? ORDER BY created_at DESC LIMIT 1",
            (device_id,),
        )
        return dict(rows[0]) if rows else None
    finally:
        await db.close()


async def get_recent_snapshots(limit: int = 50) -> List[Dict[str, Any]]:
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            """SELECT ds.*, d.ip, d.hostname
               FROM device_snapshots ds
               JOIN devices d ON d.id = ds.device_id
               ORDER BY ds.created_at DESC LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def update_device_hardware(device_id: int, hardware_json: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE devices SET hardware_json = ? WHERE id = ?",
            (hardware_json, device_id),
        )
        await db.commit()
    finally:
        await db.close()
