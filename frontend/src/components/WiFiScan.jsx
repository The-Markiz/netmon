import React, { useState, useEffect, useCallback } from 'react'
import { RefreshCw, Wifi, WifiOff, Signal, Radio, Shield, ArrowUpDown, Clock } from 'lucide-react'

const API_BASE = '/api'

function signalQuality(dbm) {
  if (dbm >= -50) return { label: 'Отличный', level: 'excellent', color: '#22c55e', pct: 100 }
  if (dbm >= -60) return { label: 'Хороший', level: 'good', color: '#84cc16', pct: 80 }
  if (dbm >= -70) return { label: 'Средний', level: 'fair', color: '#f59e0b', pct: 60 }
  if (dbm >= -80) return { label: 'Слабый', level: 'weak', color: '#f97316', pct: 40 }
  return { label: 'Очень слабый', level: 'poor', color: '#ef4444', pct: 20 }
}

function SignalBar({ dbm }) {
  const q = signalQuality(dbm)
  return (
    <div className="wifi-signal-cell">
      <div className="wifi-signal-bar">
        <div
          className={`wifi-signal-fill wifi-signal-${q.level}`}
          style={{ width: `${q.pct}%` }}
        />
      </div>
      <span className="wifi-signal-label" style={{ color: q.color }}>{dbm} dBm</span>
    </div>
  )
}

export default function WiFiScan() {
  const [networks, setNetworks] = useState([])
  const [interfaces, setInterfaces] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastScan, setLastScan] = useState(null)
  const [error, setError] = useState(null)
  const [sortKey, setSortKey] = useState('signal')
  const [sortDir, setSortDir] = useState('desc')

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [netRes, ifaceRes] = await Promise.all([
        fetch(`${API_BASE}/wifi/scan`),
        fetch(`${API_BASE}/wifi/interfaces`),
      ])

      if (netRes.ok) {
        const netData = await netRes.json()
        setNetworks(netData.networks || [])
      }
      if (ifaceRes.ok) {
        const ifaceData = await ifaceRes.json()
        setInterfaces(ifaceData.interfaces || [])
      }
      setLastScan(new Date())
    } catch (e) {
      setError('Ошибка сети при сканировании WiFi')
      console.error('WiFi scan failed:', e)
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const sorted = [...networks].sort((a, b) => {
    let va, vb
    switch (sortKey) {
      case 'ssid': va = a.ssid || ''; vb = b.ssid || ''; break
      case 'signal': va = a.signal_dbm || -100; vb = b.signal_dbm || -100; break
      case 'channel': va = parseInt(a.channel) || 0; vb = parseInt(b.channel) || 0; break
      case 'bssid': va = a.bssid || ''; vb = b.bssid || ''; break
      case 'security': va = a.authentication || a.security || ''; vb = b.authentication || b.security || ''; break
      default: va = a.signal_dbm || -100; vb = b.signal_dbm || -100;
    }
    if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase() }
    return sortDir === 'desc' ? (vb > va ? 1 : -1) : (va > vb ? 1 : -1)
  })

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return null
    return <ArrowUpDown size={12} className="sort-icon-active" />
  }

  const connectedInterfaces = interfaces.filter(i => i.state === 'connected' || i.connected_ssid)

  return (
    <div className="wifi-scan-page">
      {/* Interface info */}
      {connectedInterfaces.length > 0 && (
        <div className="wifi-interface-section">
          <h3 className="section-title"><Wifi size={18} /> Подключённые интерфейсы</h3>
          <div className="wifi-interface-cards">
            {connectedInterfaces.map((iface, i) => (
              <div key={i} className="wifi-interface-card">
                <div className="wifi-iface-header">
                  <Wifi size={16} className="wifi-iface-icon" />
                  <span className="wifi-iface-name">{iface.name || iface.interface}</span>
                  <span className="wifi-iface-state connected">Подключено</span>
                </div>
                <div className="wifi-iface-details">
                  {iface.connected_ssid && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Сеть:</span>
                      <span className="wifi-iface-value">{iface.connected_ssid}</span>
                    </div>
                  )}
                  {iface.connected_bssid && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">BSSID:</span>
                      <span className="wifi-iface-value mono">{iface.connected_bssid}</span>
                    </div>
                  )}
                  {iface.signal_percent && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Сигнал:</span>
                      <span className="wifi-iface-value">{iface.signal_percent}</span>
                    </div>
                  )}
                  {iface.radio_type && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Тип:</span>
                      <span className="wifi-iface-value">{iface.radio_type}</span>
                    </div>
                  )}
                  {iface.channel && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Канал:</span>
                      <span className="wifi-iface-value">{iface.channel}</span>
                    </div>
                  )}
                  {iface.receive_rate && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Приём:</span>
                      <span className="wifi-iface-value">{iface.receive_rate}</span>
                    </div>
                  )}
                  {iface.transmit_rate && (
                    <div className="wifi-iface-row">
                      <span className="wifi-iface-label">Передача:</span>
                      <span className="wifi-iface-value">{iface.transmit_rate}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="wifi-toolbar">
        <div className="wifi-toolbar-left">
          <h3 className="wifi-toolbar-title">
            <Radio size={16} />
            Доступные сети ({sorted.length})
          </h3>
          {lastScan && (
            <span className="wifi-last-scan">
              <Clock size={12} />
              {lastScan.toLocaleTimeString('ru-RU')}
            </span>
          )}
        </div>
        <button
          className={`wifi-refresh-btn ${loading ? 'loading' : ''}`}
          onClick={fetchData}
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          {loading ? 'Сканирование...' : 'Обновить'}
        </button>
      </div>

      {error && (
        <div className="wifi-error">{error}</div>
      )}

      {/* Table */}
      <div className="wifi-table-container">
        <table className="wifi-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('ssid')} className="sortable">
                <div className="th-content">SSID <SortIcon col="ssid" /></div>
              </th>
              <th onClick={() => handleSort('bssid')} className="sortable">
                <div className="th-content">BSSID <SortIcon col="bssid" /></div>
              </th>
              <th onClick={() => handleSort('signal')} className="sortable">
                <div className="th-content">Сигнал <SortIcon col="signal" /></div>
              </th>
              <th onClick={() => handleSort('channel')} className="sortable">
                <div className="th-content">Канал <SortIcon col="channel" /></div>
              </th>
              <th>Тип радио</th>
              <th onClick={() => handleSort('security')} className="sortable">
                <div className="th-content">Безопасность <SortIcon col="security" /></div>
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((net, i) => {
              const secLabel = net.authentication || net.security || net.encryption || '—'
              return (
                <tr key={i} className="wifi-row">
                  <td className="wifi-ssid">
                    <Wifi size={14} className="wifi-ssid-icon" />
                    {net.ssid || <span className="wifi-hidden">Скрытая сеть</span>}
                  </td>
                  <td className="cell-mono">{net.bssid || '—'}</td>
                  <td>
                    <SignalBar dbm={net.signal_dbm || 0} />
                  </td>
                  <td className="cell-center">{net.channel || '—'}</td>
                  <td className="cell-center">{net.radio_type || '—'}</td>
                  <td>
                    <span className="wifi-security-badge">{secLabel}</span>
                  </td>
                </tr>
              )
            })}
            {sorted.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="empty-state">
                  WiFi сети не обнаружены. Убедитесь, что WiFi адаптер активен.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
