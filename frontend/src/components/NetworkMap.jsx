import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import {
  ZoomIn, ZoomOut, Maximize, RefreshCw, Tag, X,
  Server, Monitor as MonitorIcon, Wifi, HelpCircle,
  MapPin, Clock, Radar, Shield, Globe, Cpu, HardDrive,
  Activity, AlertTriangle, CheckCircle, Smartphone, Router,
  ArrowRight, Fingerprint, Zap, Eye, ShieldAlert, ShieldCheck, Printer, Camera, Radio, MonitorSpeaker
} from 'lucide-react'
import { Network as VisNetwork } from 'vis-network'
import { DataSet } from 'vis-data'

const TYPE_COLORS = {
  router: '#f59e0b',
  server: '#3b82f6',
  pc: '#10b981',
  switch: '#8b5cf6',
  firewall: '#ef4444',
  iot: '#ec4899',
  phone: '#06b6d4',
  printer: '#a855f7',
  camera: '#f97316',
  media: '#14b8a6',
  nas: '#6366f1',
  wap: '#22d3ee',
  unknown: '#64748b',
}

const TYPE_ICONS = {
  router: Router,
  server: Server,
  pc: MonitorIcon,
  switch: Zap,
  firewall: Shield,
  iot: Cpu,
  phone: Smartphone,
  printer: Printer,
  camera: Camera,
  media: MonitorSpeaker,
  nas: HardDrive,
  wap: Wifi,
  unknown: HelpCircle,
}

const TYPE_LABELS = {
  router: 'Маршрутизатор',
  server: 'Сервер',
  pc: 'ПК',
  switch: 'Коммутатор',
  firewall: 'Межсетевой экран',
  iot: 'IoT / Датчики',
  phone: 'Телефон',
  printer: 'Принтер',
  camera: 'Камера',
  media: 'Медиа',
  nas: 'Хранилище (NAS)',
  wap: 'Точка доступа',
  unknown: 'Неизвестно',
}

const ALL_TYPES = Object.keys(TYPE_COLORS)

const PORT_CATEGORIES = {
  web: { ports: [80, 443, 8080, 8443, 8000, 3000, 5000, 8001, 8888], label: 'Веб-сервисы', icon: Globe, color: '#3b82f6' },
  remote: { ports: [22, 23, 3389, 5900, 5901, 445, 135, 139], label: 'Удалённый доступ', icon: Eye, color: '#f59e0b' },
  database: { ports: [3306, 5432, 1433, 27017, 6379, 1521, 9042, 9200, 5984], label: 'Базы данных', icon: HardDrive, color: '#8b5cf6' },
  network: { ports: [21, 25, 53, 67, 68, 69, 161, 162, 520, 68, 123], label: 'Сетевые сервисы', icon: Network, color: '#06b6d4' },
  media: { ports: [1935, 554, 8554, 4000, 4001, 7000, 5004], label: 'Медиа / Стриминг', icon: Activity, color: '#ec4899' },
  iot: { ports: [1883, 8883, 5683, 9100, 5222, 5228, 11211, 2181, 9090, 18080], label: 'IoT / Мониторинг', icon: Cpu, color: '#f43f5e' },
}

function Network() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5v14"/></svg> }

function getServiceCategory(port) {
  for (const [key, cat] of Object.entries(PORT_CATEGORIES)) {
    if (cat.ports.includes(port)) return { key, ...cat }
  }
  return null
}

function calcUptime(firstSeen, lastSeen) {
  if (!firstSeen || !lastSeen) return null
  const diff = new Date(lastSeen) - new Date(firstSeen)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(hours / 24)
  if (days > 30) return `${Math.floor(days / 30)}м ${days % 30}д`
  if (days > 0) return `${days}д ${hours % 24}ч`
  if (hours > 0) return `${hours}ч ${Math.floor((diff % 3600000) / 60000)}м`
  return `${Math.max(1, Math.floor(diff / 60000))}м`
}

function DeviceInfoPanel({ device, onClose }) {
  if (!device) return null

  const color = TYPE_COLORS[device.type] || TYPE_COLORS.unknown
  const typeLabel = TYPE_LABELS[device.type] || 'Неизвестно'
  const Icon = TYPE_ICONS[device.type] || HelpCircle
  const ports = device.ports || []
  const uptime = calcUptime(device.first_seen, device.last_seen)
  const isOnline = device.status === 'online'

  const portCategories = useMemo(() => {
    const cats = {}
    ports.forEach(p => {
      const cat = getServiceCategory(p.port)
      const key = cat ? cat.key : 'other'
      if (!cats[key]) cats[key] = { label: cat?.label || 'Другие порты', icon: cat?.icon || HelpCircle, color: cat?.color || '#64748b', ports: [] }
      cats[key].ports.push(p)
    })
    return Object.entries(cats).sort((a, b) => b[1].ports.length - a[1].ports.length)
  }, [ports])

  return (
    <div className="device-info-panel">
      <div className="panel-header">
        <h3>Устройство</h3>
        <button className="panel-close" onClick={onClose}>
          <X size={18} />
        </button>
      </div>

      <div className="panel-body">
        {/* Hero section */}
        <div className="panel-hero">
          <div className="panel-device-icon" style={{ backgroundColor: color + '22', color, borderColor: color + '44' }}>
            <Icon size={32} />
          </div>
          <div className="panel-device-name">{device.hostname || device.ip}</div>
          <div className="panel-device-type" style={{ color }}>{typeLabel}</div>
          <div className="panel-status-row">
            <span className={`status-pill ${isOnline ? 'online' : 'offline'}`}>
              <span className="status-dot-lg" />
              {isOnline ? 'Онлайн' : 'Оффлайн'}
            </span>
            {device.sensors?.is_sensor_device && (
              <span className="status-pill sensors">
                <Cpu size={12} />
                {device.sensors.sensor_count} датчиков
              </span>
            )}
          </div>
        </div>

        {/* Quick stats row */}
        <div className="panel-stats-row">
          <div className="panel-stat">
            <Shield size={14} />
            <span className="stat-val">{ports.length}</span>
            <span className="stat-lbl">порта</span>
          </div>
          <div className="panel-stat">
            <Clock size={14} />
            <span className="stat-val">{uptime || '—'}</span>
            <span className="stat-lbl">видимость</span>
          </div>
          <div className="panel-stat">
            <Fingerprint size={14} />
            <span className="stat-val">{device.mac ? '✓' : '—'}</span>
            <span className="stat-lbl">MAC</span>
          </div>
        </div>

        {/* Network section */}
        <div className="panel-section">
          <h4><Globe size={13} /> Сеть</h4>
          <div className="detail-rows">
            <div className="detail-row">
              <span className="dl">IP-адрес</span>
              <span className="dv mono">{device.ip}</span>
            </div>
            <div className="detail-row">
              <span className="dl">MAC-адрес</span>
              <span className="dv mono">{device.mac || '—'}</span>
            </div>
            <div className="detail-row">
              <span className="dl">Подсеть</span>
              <span className="dv mono subnet-badge">{device.subnet || '—'}</span>
            </div>
            <div className="detail-row">
              <span className="dl">Хостнейм</span>
              <span className="dv">{device.hostname || '—'}</span>
            </div>
            <div className="detail-row">
              <span className="dl">Вендор</span>
              <span className="dv">{device.vendor || '—'}</span>
            </div>
          </div>
        </div>

        {/* System section */}
        <div className="panel-section">
          <h4><Cpu size={13} /> Система</h4>
          <div className="detail-rows">
            <div className="detail-row">
              <span className="dl">ОС</span>
              <span className="dv">{device.os_guess || 'Не определена'}</span>
            </div>
            <div className="detail-row">
              <span className="dl">Тип устройства</span>
              <span className="dv" style={{ color }}>{typeLabel}</span>
            </div>
            {device.group_name && (
              <div className="detail-row">
                <span className="dl">Группа</span>
                <span className="dv">{device.group_name}</span>
              </div>
            )}
          </div>
        </div>

        {/* Hardware section */}
        {device.hardware_json && (() => {
          let hw
          try { hw = typeof device.hardware_json === 'string' ? JSON.parse(device.hardware_json) : device.hardware_json } catch { return null }
          if (!hw || (!hw.cpu_model && !hw.ram_total_gb && !hw.disk_total_gb)) return null
          const ramPct = hw.ram_total_gb > 0 ? Math.round((hw.ram_used_gb || 0) / hw.ram_total_gb * 100) : 0
          const diskPct = hw.disk_total_gb > 0 ? Math.round((hw.disk_used_gb || 0) / hw.disk_total_gb * 100) : 0
          return (
            <div className="panel-section">
              <h4><HardDrive size={13} /> Железо</h4>
              <div className="detail-rows">
                {hw.cpu_model && (
                  <div className="detail-row">
                    <span className="dl">CPU</span>
                    <span className="dv sm">{hw.cpu_model}{hw.cpu_cores ? ` (${hw.cpu_cores} ядра)` : ''}</span>
                  </div>
                )}
                {hw.ram_total_gb > 0 && (
                  <div className="detail-row">
                    <span className="dl">RAM</span>
                    <span className="dv">
                      <span className="hw-value">{(hw.ram_used_gb || 0).toFixed(1)} / {hw.ram_total_gb.toFixed(1)} ГБ</span>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${ramPct}%`, background: ramPct > 85 ? 'var(--red)' : ramPct > 60 ? 'var(--amber)' : 'var(--green)' }} />
                      </div>
                    </span>
                  </div>
                )}
                {hw.disk_total_gb > 0 && (
                  <div className="detail-row">
                    <span className="dl">Диск</span>
                    <span className="dv">
                      <span className="hw-value">{(hw.disk_used_gb || 0).toFixed(1)} / {hw.disk_total_gb.toFixed(1)} ГБ</span>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${diskPct}%`, background: diskPct > 85 ? 'var(--red)' : diskPct > 60 ? 'var(--amber)' : 'var(--green)' }} />
                      </div>
                    </span>
                  </div>
                )}
                {hw.uptime_hours != null && (
                  <div className="detail-row">
                    <span className="dl">Аптайм</span>
                    <span className="dv">{hw.uptime_hours >= 24 ? `${Math.floor(hw.uptime_hours / 24)}д ${hw.uptime_hours % 24}ч` : `${hw.uptime_hours}ч`}</span>
                  </div>
                )}
              </div>
            </div>
          )
        })()}

        {/* Time section */}
        <div className="panel-section">
          <h4><Clock size={13} /> Временные метки</h4>
          <div className="detail-rows">
            <div className="detail-row">
              <span className="dl">Первое обнаружение</span>
              <span className="dv sm">
                {device.first_seen ? new Date(device.first_seen).toLocaleString('ru-RU') : '—'}
              </span>
            </div>
            <div className="detail-row">
              <span className="dl">Последнее обнаружение</span>
              <span className="dv sm">
                {device.last_seen ? new Date(device.last_seen).toLocaleString('ru-RU') : '—'}
              </span>
            </div>
          </div>
        </div>

        {/* Sensors */}
        {device.sensors?.is_sensor_device && (
          <div className="panel-section">
            <h4><Activity size={13} /> Датчики и сервисы ({device.sensors.sensor_count})</h4>
            <div className="sensor-tags">
              {device.sensors.sensor_types.map((sensor, i) => (
                <span key={i} className="sensor-tag">{sensor}</span>
              ))}
            </div>
          </div>
        )}

        {/* Ports grouped by category */}
        {portCategories.length > 0 && (
          <div className="panel-section">
            <h4><Shield size={13} /> Открытые порты ({ports.length})</h4>
            {portCategories.map(([key, cat]) => (
              <div key={key} className="port-group">
                <div className="port-group-header" style={{ borderLeftColor: cat.color }}>
                  <cat.icon size={12} style={{ color: cat.color }} />
                  <span>{cat.label}</span>
                  <span className="port-badge">{cat.ports.length}</span>
                </div>
                <div className="port-items">
                  {cat.ports.map((p, i) => (
                    <div key={i} className="port-row">
                      <span className="port-num">{p.port}</span>
                      <span className="port-svc">{p.service || '—'}</span>
                      <span className="port-ver">{p.version || ''}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {ports.length === 0 && (
          <div className="panel-section">
            <h4><Shield size={13} /> Порты</h4>
            <p className="panel-empty">Открытые порты не обнаружены</p>
          </div>
        )}

        {/* Antivirus / Security section */}
        {(() => {
          const hw = device.hardware_json ? JSON.parse(device.hardware_json) : {}
          const av = hw.antivirus || []
          if (av.length === 0) return null
          return (
            <div className="panel-section">
              <h4><ShieldAlert size={13} /> Безопасность</h4>
              <div className="av-list">
                {av.map((product, i) => (
                  <div key={i} className="av-item">
                    <ShieldCheck size={14} className="av-icon" />
                    <span className="av-name">{product.name}</span>
                    {product.vendor && <span className="av-vendor">{product.vendor}</span>}
                    <span className="av-source">{product.source}</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })()}
      </div>
    </div>
  )
}

export default function NetworkMap({ devices, selectedDevice, onSelectDevice, scanStatus }) {
  const containerRef = useRef(null)
  const networkRef = useRef(null)
  const nodesRef = useRef(null)
  const edgesRef = useRef(null)
  const [showLabels, setShowLabels] = useState(true)
  const [nodeCount, setNodeCount] = useState(0)
  const [scanTriggered, setScanTriggered] = useState(false)

  const triggerScan = useCallback(async () => {
    try {
      const res = await fetch('/api/scan/trigger', { method: 'POST' })
      if (res.ok) {
        setScanTriggered(true)
        setTimeout(() => setScanTriggered(false), 3000)
      }
    } catch (e) {
      console.error('Failed to trigger scan:', e)
    }
  }, [])

  const buildNetwork = useCallback(() => {
    if (!containerRef.current) return

    const nodes = new DataSet()
    const edges = new DataSet()
    nodesRef.current = nodes
    edgesRef.current = edges

    const network = new VisNetwork(containerRef.current, { nodes, edges }, {
      nodes: {
        font: {
          color: '#e2e8f0',
          size: 13,
          face: 'system-ui',
          strokeWidth: 3,
          strokeColor: '#0a0e1a',
          align: 'bottom',
          multi: false,
          bold: { color: '#f1f5f9' },
          scaling: {
            enabled: true,
            min: 10,
            max: 24,
            maxVisible: 24,
            drawThreshold: 0,
          },
        },
        borderWidth: 2,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.4)', size: 8, x: 0, y: 2 },
        shape: 'dot',
        scaling: {
          min: 18,
          max: 42,
          label: {
            enabled: true,
            min: 10,
            max: 24,
            maxVisible: 24,
            drawThreshold: 0,
          },
        },
      },
      edges: {
        color: { color: '#334155', highlight: '#60a5fa', hover: '#94a3b8', opacity: 0.6 },
        width: 1.5,
        smooth: { enabled: true, type: 'continuous', roundness: 0.15 },
        arrows: { to: { enabled: false } },
        hoverWidth: 2.5,
        selectionWidth: 2.5,
        font: { size: 0, strokeWidth: 0 },
      },
      physics: {
        enabled: true,
        barnesHut: {
          gravitationalConstant: -5000,
          centralGravity: 0.35,
          springLength: 160,
          springConstant: 0.08,
          damping: 0.15,
        },
        stabilization: {
          enabled: true,
          iterations: 300,
          updateInterval: 25,
          fit: true,
        },
      },
      interaction: {
        hover: true,
        tooltipDelay: 80,
        navigationButtons: false,
        keyboard: false,
        zoomView: true,
        dragView: true,
        dragNodes: true,
        hideEdgesOnDrag: false,
        multiselect: false,
        zoomSpeed: 1.0,
      },
      layout: {
        improvedLayout: true,
        hierarchical: false,
      },
    })

    // Enforce zoom limits
    network.on('zoom', (params) => {
      if (params.scale < 0.15) network.moveTo({ scale: 0.15 })
      if (params.scale > 6) network.moveTo({ scale: 6 })
    })

    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0]
        const nodeData = nodes.get(nodeId)
        if (nodeData?.rawData) onSelectDevice(nodeData.rawData)
      } else {
        onSelectDevice(null)
      }
    })

    network.once('stabilizationIterationsDone', () => {
      setTimeout(() => network.fit({ animation: { duration: 600 } }), 400)
    })

    networkRef.current = network
  }, [onSelectDevice])

  useEffect(() => {
    buildNetwork()
    return () => { if (networkRef.current) { networkRef.current.destroy(); networkRef.current = null } }
  }, [buildNetwork])

  useEffect(() => {
    if (!nodesRef.current || !edgesRef.current) return

    const nodes = nodesRef.current
    const edges = edgesRef.current
    const existingEdgeIds = new Set(edges.getIds())
    const incomingIds = new Set(devices.map(d => `dev-${d.id || d.ip}`))

    new Set(nodes.getIds()).forEach(id => { if (!incomingIds.has(id)) nodes.remove(id) })

    const router = devices.find(d => d.type === 'router')
    const newEdges = []

    devices.forEach(device => {
      const nodeId = `dev-${device.id || device.ip}`
      const color = TYPE_COLORS[device.type] || TYPE_COLORS.unknown
      const isSensor = device.sensors?.is_sensor_device
      const isRouter = device.type === 'router'
      const size = isRouter ? 40 : device.type === 'server' ? 32 : isSensor ? 28 : device.type === 'phone' ? 20 : 24
      const opacity = device.status === 'online' ? 1 : 0.25
      const borderWidth = isSensor ? 3 : isRouter ? 3 : 2

      const labelParts = []
      if (showLabels) {
        labelParts.push(device.hostname || device.ip)
        if (isSensor) labelParts.push(`[${device.sensors.sensor_count} sensors]`)
      }

      nodes.update({
        id: nodeId,
        label: labelParts.join('\n'),
        color: {
          background: color,
          border: isSensor ? '#ffffff' : color,
          highlight: { background: color, border: '#ffffff' },
          hover: { background: color, border: '#f8fafc' },
        },
        size,
        opacity,
        borderWidth,
        shape: isRouter ? 'diamond' : isSensor ? 'triangle' : 'dot',
        shadow: { enabled: true, color: isRouter ? 'rgba(245,158,11,0.3)' : 'rgba(0,0,0,0.4)', size: isRouter ? 14 : 8 },
        title: [
          `${device.hostname || device.ip}`,
          `IP: ${device.ip}${device.mac ? '\nMAC: ' + device.mac : ''}`,
          `${TYPE_LABELS[device.type] || '—'} · ${device.status === 'online' ? '● Онлайн' : '○ Оффлайн'}`,
          device.os_guess ? `ОС: ${device.os_guess}` : '',
          (device.ports?.length) ? `Порты: ${device.ports.length} открытых` : '',
          isSensor ? `Датчики: ${device.sensors.sensor_types.join(', ')}` : '',
        ].filter(Boolean).join('\n'),
        rawData: device,
      })

      // Star topology: connect all devices to router
      if (router && !isRouter) {
        const routerId = `dev-${router.id || router.ip}`
        const edgeId = `edge-rtr-${nodeId}`
        if (!existingEdgeIds.has(edgeId)) {
          const edgeColor = device.status === 'online' ? '#334155' : '#1e293b'
          newEdges.push({
            id: edgeId,
            from: routerId,
            to: nodeId,
            color: { color: edgeColor, highlight: '#60a5fa', opacity: device.status === 'online' ? 0.6 : 0.2 },
            width: device.status === 'online' ? 1.5 : 0.8,
            smooth: { enabled: true, type: 'continuous', roundness: 0.15 },
          })
        }
      }

      // Peer connections: devices sharing 2+ open ports
      if (isRouter) return
      const devPorts = new Set((device.ports || []).map(p => p.port))
      devices.forEach(other => {
        if (other.id === device.id || other.type === 'router') return
        const otherPorts = new Set((other.ports || []).map(p => p.port))
        const overlap = [...devPorts].filter(p => otherPorts.has(p)).length
        if (overlap >= 2) {
          const otherId = `dev-${other.id || other.ip}`
          const edgeId = `edge-peer-${nodeId}-${otherId}`
          const reverseEdgeId = `edge-peer-${otherId}-${nodeId}`
          if (!existingEdgeIds.has(edgeId) && !existingEdgeIds.has(reverseEdgeId)) {
            newEdges.push({
              id: edgeId,
              from: nodeId,
              to: otherId,
              dashes: [5, 5],
              color: { color: '#475569', opacity: 0.35, highlight: '#60a5fa' },
              width: 1,
              smooth: { enabled: true, type: 'curvedCW', roundness: 0.1 },
            })
          }
        }
      })
    })

    if (newEdges.length > 0) edges.add(newEdges)
    setNodeCount(devices.length)
  }, [devices, showLabels])

  useEffect(() => {
    if (!networkRef.current || !nodesRef.current) return
    const fit = () => networkRef.current?.fit({ animation: { duration: 500 } })
    const t1 = setTimeout(fit, 700)
    const t2 = setTimeout(fit, 3000)
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [nodeCount])

  const handleZoomIn = () => networkRef.current?.zoomIn(0.3)
  const handleZoomOut = () => networkRef.current?.zoomOut(0.3)
  const handleFit = () => networkRef.current?.fit({ animation: { duration: 500 } })

  return (
    <div className="network-map">
      <div className="map-toolbar">
        <button className="toolbar-btn" onClick={handleZoomIn} title="Приблизить"><ZoomIn size={18} /></button>
        <button className="toolbar-btn" onClick={handleZoomOut} title="Отдалить"><ZoomOut size={18} /></button>
        <button className="toolbar-btn" onClick={handleFit} title="Вписать в экран"><Maximize size={18} /></button>
        <button className="toolbar-btn" onClick={handleFit} title="Обновить"><RefreshCw size={18} /></button>
        <button className={`toolbar-btn ${showLabels ? 'active' : ''}`} onClick={() => setShowLabels(!showLabels)} title="Метки"><Tag size={18} /></button>
        <div className="toolbar-divider" />
        <button className={`toolbar-btn ${scanTriggered ? 'scanning' : ''}`} onClick={triggerScan} title="Сканирование" disabled={scanStatus != null}><Radar size={18} /></button>
      </div>

      {scanStatus && (
        <div className="scan-indicator">
          <RefreshCw size={14} className="spin" />
          <span>Сканирование: {scanStatus.percent || scanStatus.progress || 0}% — {scanStatus.ip || ''}</span>
        </div>
      )}

      <div className="map-legend">
        <span className="legend-title">Типы:</span>
        {Object.entries(TYPE_COLORS).filter(([k]) => k !== 'unknown').map(([type, c]) => (
          <div key={type} className="legend-item">
            <span className="legend-dot" style={{ backgroundColor: c }} />
            <span>{TYPE_LABELS[type]}</span>
          </div>
        ))}
        <div className="legend-sep" />
        <div className="legend-item"><span className="legend-line solid" /><span>Связь</span></div>
        <div className="legend-item"><span className="legend-line dashed" /><span>Общие сервисы</span></div>
      </div>

      <div ref={containerRef} className="map-canvas" />

      <DeviceInfoPanel device={selectedDevice} onClose={() => onSelectDevice(null)} />
    </div>
  )
}
