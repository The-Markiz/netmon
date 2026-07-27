import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from main import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── Stats ──

@pytest.mark.asyncio
async def test_stats(client):
    r = await client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_devices" in data
    assert "online" in data
    assert "offline" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], dict)


# ── Devices ──

@pytest.mark.asyncio
async def test_list_devices(client):
    r = await client.get("/api/devices")
    assert r.status_code == 200
    data = r.json()
    assert "devices" in data
    assert "total" in data
    assert isinstance(data["devices"], list)


@pytest.mark.asyncio
async def test_get_device_not_found(client):
    r = await client.get("/api/devices/999.999.999.999")
    assert r.status_code == 404


# ── Alerts ──

@pytest.mark.asyncio
async def test_list_alerts(client):
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    data = r.json()
    assert "alerts" in data
    assert "severity_counts" in data
    assert isinstance(data["alerts"], list)


@pytest.mark.asyncio
async def test_list_alerts_with_filters(client):
    r = await client.get("/api/alerts", params={"severity": "critical", "limit": 10})
    assert r.status_code == 200
    data = r.json()
    for alert in data["alerts"]:
        assert alert["severity"] == "critical"


@pytest.mark.asyncio
async def test_acknowledge_alert_not_found(client):
    r = await client.post("/api/alerts/99999/acknowledge")
    assert r.status_code == 404


# ── Alert Rules ──

@pytest.mark.asyncio
async def test_list_alert_rules(client):
    r = await client.get("/api/alerts/rules")
    assert r.status_code == 200
    data = r.json()
    assert "rules" in data
    assert isinstance(data["rules"], dict)
    assert "new_device" in data["rules"]
    assert "device_offline" in data["rules"]


@pytest.mark.asyncio
async def test_toggle_alert_rule(client):
    r = await client.get("/api/alerts/rules")
    initial_enabled = r.json()["rules"]["new_device"]["enabled"]

    r = await client.put(
        "/api/alerts/rules/new_device",
        json={"enabled": not initial_enabled},
    )
    assert r.status_code == 200

    r = await client.get("/api/alerts/rules")
    assert r.json()["rules"]["new_device"]["enabled"] == (not initial_enabled)

    # Restore
    await client.put(
        "/api/alerts/rules/new_device",
        json={"enabled": initial_enabled},
    )


@pytest.mark.asyncio
async def test_toggle_alert_rule_not_found(client):
    r = await client.put("/api/alerts/rules/nonexistent", json={"enabled": True})
    assert r.status_code == 404


# ── Scanner Config ──

@pytest.mark.asyncio
async def test_get_scanner_config(client):
    r = await client.get("/api/scanner/config")
    assert r.status_code == 200
    data = r.json()
    assert "interval" in data
    assert "subnet" in data
    assert isinstance(data["interval"], int)


@pytest.mark.asyncio
async def test_update_scanner_config(client):
    r = await client.put("/api/scanner/config", json={"interval": 60})
    assert r.status_code == 200
    assert r.json()["interval"] == 60

    # Restore
    await client.put("/api/scanner/config", json={"interval": 30})


@pytest.mark.asyncio
async def test_update_scanner_config_invalid_interval(client):
    r = await client.put("/api/scanner/config", json={"interval": 5})
    assert r.status_code == 400

    r = await client.put("/api/scanner/config", json={"interval": 99999})
    assert r.status_code == 400


# ── Scan ──

@pytest.mark.asyncio
async def test_scan_status(client):
    r = await client.get("/api/scan/status")
    assert r.status_code == 200
    data = r.json()
    assert "running" in data
    assert "progress" in data


@pytest.mark.asyncio
async def test_scan_history(client):
    r = await client.get("/api/scan/history")
    assert r.status_code == 200
    data = r.json()
    assert "history" in data
    assert isinstance(data["history"], list)


# ── Dashboard Configs ──

@pytest.mark.asyncio
async def test_dashboard_configs(client):
    r = await client.get("/api/dashboard/configs")
    assert r.status_code == 200
    data = r.json()
    assert "configs" in data
    assert isinstance(data["configs"], list)


# ── Export ──

@pytest.mark.asyncio
async def test_export_devices_csv(client):
    r = await client.get("/api/export/devices")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert "netmon-devices.csv" in r.headers.get("content-disposition", "")
    lines = r.text.strip().split("\n")
    assert len(lines) >= 1
    assert "IP" in lines[0]
    assert "MAC" in lines[0]
