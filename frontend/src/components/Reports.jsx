import React, { useState, useEffect, useCallback } from 'react'
import { FileText, Download, Server, Monitor, Wifi, WifiOff, AlertTriangle, Clock, Cpu, HardDrive, MemoryStick, ArrowUpDown, ChevronDown, ChevronRight } from 'lucide-react'

const TYPE_LABELS = {
  router: 'Маршрутизатор', server: 'Сервер', pc: 'ПК', switch: 'Коммутатор', iot: 'IoT', phone: 'Телефон', unknown: 'Неизвестно',
}
const TYPE_COLORS = {
  router: '#f59e0b', server: '#3b82f6', pc: '#10b981', switch: '#8b5cf6', iot: '#ec4899', phone: '#06b6d4', unknown: '#64748b',
}

export default function Reports({ devices }) {
  const [changes, setChanges] = useState([])
  const [showChanges, setShowChanges] = useState(true)
  const [sortField, setSortField] = useState('ip')
  const [sortDir, setSortDir] = useState('asc')

  const fetchChanges = useCallback(async () => {
    try {
      const res = await fetch('/api/reports/changes')
      if (res.ok) {
        const data = await res.json()
        setChanges(data.changes || data || [])
      }
    } catch (e) {
      console.error('Failed to fetch changes:', e)
    }
  }, [])

  useEffect(() => { fetchChanges() }, [fetchChanges])

  const online = devices.filter(d => d.status === 'online')
  const offline = devices.filter(d => d.status !== 'online')
  const byType = {}
  devices.forEach(d => { const t = d.type || 'unknown'; byType[t] = (byType[t] || 0) + 1 })
  const byGroup = {}
  devices.forEach(d => { const g = d.group_name || 'Без группы'; byGroup[g] = (byGroup[g] || 0) + 1 })

  const sorted = [...devices].sort((a, b) => {
    let av = a[sortField] || '', bv = b[sortField] || ''
    if (sortField === 'ports') { av = (a.ports || []).length; bv = (b.ports || []).length }
    if (typeof av === 'string') { av = av.toLowerCase(); bv = bv.toLowerCase() }
    if (av < bv) return sortDir === 'asc' ? -1 : 1
    if (av > bv) return sortDir === 'asc' ? 1 : -1
    return 0
  })

  const toggleSort = (field) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  const downloadCSV = () => { window.open('/api/reports/devices/csv', '_blank') }

  const formatHw = (hw) => {
    if (!hw) return null
    try { return typeof hw === 'string' ? JSON.parse(hw) : hw } catch { return null }
  }

  return (
    <div className="reports-page">
      <div className="reports-toolbar">
        <h2 className="reports-title"><FileText size={18} /> Отчёты</h2>
        <button className="export-btn" onClick={downloadCSV}><Download size={14} /> Экспорт CSV</button>
      </div>

      {/* Summary cards */}
      <div className="report-summary">
        <div className="report-card">
          <div className="report-card-icon" style={{ background: 'rgba(148,163,184,0.1)', color: 'var(--text-secondary)' }}><Server size={20} /></div>
          <div className="report-card-info"><span className="report-card-label">Всего</span><span className="report-card-value">{devices.length}</span></div>
        </div>
        <div className="report-card">
          <div className="report-card-icon" style={{ background: 'var(--green-dim)', color: 'var(--green)' }}><Wifi size={20} /></div>
          <div className="report-card-info"><span className="report-card-label">Онлайн</span><span className="report-card-value">{online.length}</span></div>
        </div>
        <div className="report-card">
          <div className="report-card-icon" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}><WifiOff size={20} /></div>
          <div className="report-card-info"><span className="report-card-label">Оффлайн</span><span className="report-card-value">{offline.length}</span></div>
        </div>
        {Object.entries(byType).map(([type, count]) => (
          <div key={type} className="report-card">
            <div className="report-card-icon" style={{ background: (TYPE_COLORS[type] || '#64748b') + '22', color: TYPE_COLORS[type] || '#64748b' }}><Monitor size={20} /></div>
            <div className="report-card-info"><span className="report-card-label">{TYPE_LABELS[type] || type}</span><span className="report-card-value">{count}</span></div>
          </div>
        ))}
        {Object.entries(byGroup).filter(([g]) => g !== 'Без группы').map(([group, count]) => (
          <div key={group} className="report-card">
            <div className="report-card-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}><FileText size={20} /></div>
            <div className="report-card-info"><span className="report-card-label">{group}</span><span className="report-card-value">{count}</span></div>
          </div>
        ))}
      </div>

      {/* Device table */}
      <div className="report-table-wrap">
        <h3 className="report-section-title">Устройства ({devices.length})</h3>
        <div className="report-table-container">
          <table className="report-table">
            <thead>
              <tr>
                {[
                  { key: 'ip', label: 'IP' },
                  { key: 'hostname', label: 'Хостнейм' },
                  { key: 'type', label: 'Тип' },
                  { key: 'status', label: 'Статус' },
                  { key: 'mac', label: 'MAC' },
                  { key: 'vendor', label: 'Вендор' },
                  { key: 'group_name', label: 'Группа' },
                  { key: 'ports', label: 'Порты' },
                ].map(col => (
                  <th key={col.key} className="sortable" onClick={() => toggleSort(col.key)}>
                    <span className="th-content">
                      {col.label}
                      {sortField === col.key && <ArrowUpDown size={11} style={{ opacity: 0.6 }} />}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.map(d => {
                const hw = formatHw(d.hardware_json)
                return (
                  <tr key={d.id}>
                    <td className="mono">{d.ip}</td>
                    <td>{d.hostname || '—'}</td>
                    <td><span className="type-badge" style={{ color: TYPE_COLORS[d.type] || '#64748b' }}>{TYPE_LABELS[d.type] || d.type}</span></td>
                    <td><span className={`status-badge ${d.status === 'online' ? 'online' : 'offline'}`}>{d.status === 'online' ? 'Онлайн' : 'Оффлайн'}</span></td>
                    <td className="mono" style={{ fontSize: 11 }}>{d.mac || '—'}</td>
                    <td>{d.vendor || '—'}</td>
                    <td>{d.group_name || <span style={{ color: 'var(--text-dim)' }}>—</span>}</td>
                    <td>{(d.ports || []).length}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Change history */}
      <div className="report-table-wrap">
        <div className="report-section-header" onClick={() => setShowChanges(!showChanges)} style={{ cursor: 'pointer' }}>
          {showChanges ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <h3 className="report-section-title" style={{ marginBottom: 0 }}>История изменений ({changes.length})</h3>
        </div>
        {showChanges && (
          <div className="report-table-container" style={{ marginTop: 8 }}>
            {changes.length === 0 ? (
              <div className="empty-state">Изменений не зафиксировано</div>
            ) : (
              <table className="report-table">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>Устройство</th>
                    <th>IP</th>
                    <th>Тип</th>
                    <th>Описание</th>
                  </tr>
                </thead>
                <tbody>
                  {changes.map((c, i) => (
                    <tr key={c.id || i}>
                      <td style={{ whiteSpace: 'nowrap' }}>{c.timestamp ? new Date(c.timestamp).toLocaleString('ru-RU') : '—'}</td>
                      <td>{c.device_name || c.hostname || '—'}</td>
                      <td className="mono">{c.ip || '—'}</td>
                      <td>{c.change_type || c.type || '—'}</td>
                      <td style={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.description || c.detail || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
