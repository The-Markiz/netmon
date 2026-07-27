import React, { useState, useEffect, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import NetworkMap from './components/NetworkMap'
import DeviceList from './components/DeviceList'
import AlertDashboard from './components/AlertDashboard'
import Settings from './components/Settings'
import StatsBar from './components/StatsBar'
import DeviceTree from './components/DeviceTree'
import Reports from './components/Reports'
import WiFiScan from './components/WiFiScan'

const API_BASE = '/api'

export default function App() {
  const [route, setRoute] = useState('/')
  const [devices, setDevices] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total: 0, online: 0, offline: 0, alerts: { critical: 0, warning: 0, info: 0 } })
  const [connected, setConnected] = useState(false)
  const [scanStatus, setScanStatus] = useState(null)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [config, setConfig] = useState(null)

  const fetchDevices = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/devices`)
      if (res.ok) {
        const data = await res.json()
        setDevices(data.devices || data || [])
      }
    } catch (e) {
      console.error('Failed to fetch devices:', e)
    }
  }, [])

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/alerts`)
      if (res.ok) {
        const data = await res.json()
        setAlerts(data.alerts || data || [])
      }
    } catch (e) {
      console.error('Failed to fetch alerts:', e)
    }
  }, [])

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`)
      if (res.ok) {
        const data = await res.json()
        setStats(data)
      }
    } catch (e) {
      console.error('Failed to fetch stats:', e)
    }
  }, [])

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/configs`)
      if (res.ok) {
        const data = await res.json()
        setConfig(data.configs || [])
      }
    } catch (e) {
      console.error('Failed to fetch config:', e)
    }
  }, [])

  const acknowledgeAlert = useCallback(async (alertId) => {
    try {
      const res = await fetch(`${API_BASE}/alerts/${alertId}/acknowledge`, { method: 'POST' })
      if (res.ok) {
        setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, acknowledged: 1 } : a))
      }
    } catch (e) {
      console.error('Failed to acknowledge alert:', e)
    }
  }, [])

  const saveConfig = useCallback(async (newConfig) => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/configs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig),
      })
      if (res.ok) {
        fetchConfig()
      }
    } catch (e) {
      console.error('Failed to save config:', e)
    }
  }, [fetchConfig])

  useEffect(() => {
    fetchDevices()
    fetchAlerts()
    fetchStats()
    fetchConfig()
  }, [fetchDevices, fetchAlerts, fetchStats, fetchConfig])

  useEffect(() => {
    let ws
    let reconnectTimer

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      ws = new WebSocket(`${protocol}//${window.location.host}/ws/events`)

      ws.onopen = () => setConnected(true)

      ws.onclose = () => {
        setConnected(false)
        reconnectTimer = setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        ws.close()
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          switch (msg.type) {
            case 'new_device':
              setDevices(prev => {
                const idx = prev.findIndex(d => d.id === msg.data.id || d.ip === msg.data.ip)
                if (idx >= 0) {
                  const copy = [...prev]
                  copy[idx] = { ...copy[idx], ...msg.data, status: 'online' }
                  return copy
                }
                return [...prev, { ...msg.data, status: 'online' }]
              })
              fetchStats()
              break
            case 'device_offline':
              setDevices(prev => prev.map(d =>
                (d.id === msg.data.id || d.ip === msg.data.ip)
                  ? { ...d, status: 'offline' }
                  : d
              ))
              fetchStats()
              break
            case 'new_alert':
              setAlerts(prev => [msg.data, ...prev])
              fetchStats()
              break
            case 'scan_progress':
              setScanStatus(msg.data)
              break
            case 'scan_completed':
              setScanStatus(null)
              fetchDevices()
              fetchStats()
              break
            default:
              break
          }
        } catch (e) {
          console.error('WebSocket message parse error:', e)
        }
      }
    }

    connect()

    return () => {
      clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [fetchDevices, fetchStats])

  const onlineCount = devices.filter(d => d.status === 'online').length
  const offlineCount = devices.length - onlineCount

  const renderContent = () => {
    switch (route) {
      case '/devices':
        return <DeviceList devices={devices} />
      case '/alerts':
        return <AlertDashboard alerts={alerts} onAcknowledge={acknowledgeAlert} />
      case '/settings':
        return <Settings config={config} onSave={saveConfig} />
      case '/tree':
        return <DeviceTree devices={devices} onSelectDevice={(d) => { setSelectedDevice(d); setRoute('/') }} selectedDevice={selectedDevice} />
      case '/reports':
        return <Reports devices={devices} />
      case '/wifi':
        return <WiFiScan />
      case '/':
      default:
        return (
          <NetworkMap
            devices={devices}
            selectedDevice={selectedDevice}
            onSelectDevice={setSelectedDevice}
            scanStatus={scanStatus}
          />
        )
    }
  }

  return (
    <div className="app">
      <Sidebar
        route={route}
        onNavigate={setRoute}
        connected={connected}
        onlineCount={onlineCount}
        offlineCount={offlineCount}
        totalCount={devices.length}
        alertCount={alerts.filter(a => a.acknowledged !== 1 && a.acknowledged !== true).length}
      />
      <div className="main-content">
        <StatsBar
          stats={{
            total: devices.length,
            online: onlineCount,
            offline: offlineCount,
            alerts: {
              critical: alerts.filter(a => a.severity === 'critical' && a.acknowledged !== 1 && a.acknowledged !== true).length,
              warning: alerts.filter(a => a.severity === 'warning' && a.acknowledged !== 1 && a.acknowledged !== true).length,
              info: alerts.filter(a => a.severity === 'info' && a.acknowledged !== 1 && a.acknowledged !== true).length,
            },
          }}
        />
        {renderContent()}
      </div>
    </div>
  )
}
