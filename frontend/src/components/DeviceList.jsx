import React, { useState, useMemo } from 'react'
import { Search, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Server, Monitor, Wifi, HelpCircle, Smartphone, Cpu, Globe } from 'lucide-react'

const COLUMNS = [
  { key: 'ip', label: 'IP-адрес' },
  { key: 'mac', label: 'MAC-адрес' },
  { key: 'hostname', label: 'Хостнейм' },
  { key: 'os_guess', label: 'ОС' },
  { key: 'vendor', label: 'Вендор' },
  { key: 'subnet', label: 'Подсеть' },
  { key: 'status', label: 'Статус' },
  { key: 'ports_count', label: 'Порты' },
  { key: 'type', label: 'Тип' },
  { key: 'first_seen', label: 'Первое обнаружение' },
  { key: 'last_seen', label: 'Последнее обнаружение' },
]

const TYPE_COLORS = {
  router: '#f59e0b', server: '#3b82f6', pc: '#10b981',
  switch: '#8b5cf6', iot: '#ec4899', phone: '#06b6d4', unknown: '#64748b',
}

const TYPE_LABELS = {
  router: 'Маршрутизатор', server: 'Сервер', pc: 'ПК',
  switch: 'Коммутатор', iot: 'IoT', phone: 'Телефон', unknown: 'Неизвестно',
}

function TypeIcon({ type }) {
  switch (type) {
    case 'router': return <Wifi size={16} />
    case 'server': return <Server size={16} />
    case 'pc': return <Monitor size={16} />
    case 'iot': return <Cpu size={16} />
    case 'phone': return <Smartphone size={16} />
    case 'switch': return <Globe size={16} />
    default: return <HelpCircle size={16} />
  }
}

export default function DeviceList({ devices }) {
  const [sortKey, setSortKey] = useState('ip')
  const [sortDir, setSortDir] = useState('asc')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [expandedRow, setExpandedRow] = useState(null)
  const [page, setPage] = useState(0)
  const perPage = 25

  const filtered = useMemo(() => {
    let result = [...devices]

    if (search) {
      const q = search.toLowerCase()
      result = result.filter(d =>
        (d.ip && d.ip.includes(q)) ||
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        (d.mac && d.mac.toLowerCase().includes(q)) ||
        (d.os_guess && d.os_guess.toLowerCase().includes(q)) ||
        (d.vendor && d.vendor.toLowerCase().includes(q))
      )
    }

    if (statusFilter !== 'all') {
      result = result.filter(d => d.status === statusFilter)
    }

    if (typeFilter !== 'all') {
      result = result.filter(d => d.type === typeFilter)
    }

    result.sort((a, b) => {
      let va = a[sortKey] ?? ''
      let vb = b[sortKey] ?? ''

      if (sortKey === 'ports_count') {
        va = (a.ports || []).length
        vb = (b.ports || []).length
      }

      if (typeof va === 'string') va = va.toLowerCase()
      if (typeof vb === 'string') vb = vb.toLowerCase()

      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })

    return result
  }, [devices, search, statusFilter, typeFilter, sortKey, sortDir])

  const totalPages = Math.ceil(filtered.length / perPage)
  const paged = filtered.slice(page * perPage, (page + 1) * perPage)

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return null
    return sortDir === 'asc' ? <ChevronUp size={14} /> : <ChevronDown size={14} />
  }

  const uniqueTypes = useMemo(() => {
    const types = new Set(devices.map(d => d.type).filter(Boolean))
    return Array.from(types).sort()
  }, [devices])

  return (
    <div className="device-list">
      <div className="list-toolbar">
        <div className="search-box">
          <Search size={16} />
          <input
            type="text"
            placeholder="Поиск по IP, хостнейму, MAC, ОС, вендору..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
          />
        </div>

        <div className="filter-group">
          <label>Статус:</label>
          <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(0) }}>
            <option value="all">Все</option>
            <option value="online">Онлайн</option>
            <option value="offline">Оффлайн</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Тип:</label>
          <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0) }}>
            <option value="all">Все</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>{TYPE_LABELS[t] || t}</option>
            ))}
          </select>
        </div>

        <div className="list-info">
          Найдено: {filtered.length} из {devices.length}
        </div>
      </div>

      <div className="table-container">
        <table className="device-table">
          <thead>
            <tr>
              {COLUMNS.map(col => (
                <th key={col.key} onClick={() => handleSort(col.key)} className="sortable">
                  <div className="th-content">
                    {col.label}
                    <SortIcon col={col.key} />
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paged.map((device) => {
              const id = device.id || device.ip
              const expanded = expandedRow === id
              const portsCount = (device.ports || []).length
              const hw = device.hardware_json ? JSON.parse(device.hardware_json) : {}
              const typeColor = TYPE_COLORS[device.type] || TYPE_COLORS.unknown
              return (
                <React.Fragment key={id}>
                  <tr
                    className={`device-row ${expanded ? 'expanded' : ''}`}
                    onClick={() => setExpandedRow(expanded ? null : id)}
                  >
                    <td className="cell-ip">
                      <TypeIcon type={device.type} />
                      {device.ip}
                    </td>
                    <td className="cell-mono">{device.mac || '—'}</td>
                    <td>{device.hostname || '—'}</td>
                    <td className="cell-os">{device.os_guess || '—'}</td>
                    <td>{device.vendor || '—'}</td>
                    <td className="cell-mono subnet-cell">{device.subnet || '—'}</td>
                    <td>
                      <span className={`status-badge ${device.status}`}>
                        <span className="status-dot" />
                        {device.status === 'online' ? 'Онлайн' : 'Оффлайн'}
                      </span>
                    </td>
                    <td className="cell-center">{portsCount}</td>
                    <td>
                      <span className="type-badge" style={{ color: typeColor, borderColor: typeColor + '40' }}>
                        {TYPE_LABELS[device.type] || '—'}
                      </span>
                    </td>
                    <td className="cell-date">{device.first_seen ? new Date(device.first_seen).toLocaleString('ru-RU') : '—'}</td>
                    <td className="cell-date">{device.last_seen ? new Date(device.last_seen).toLocaleString('ru-RU') : '—'}</td>
                  </tr>
                  {expanded && (
                    <tr className="device-detail-row">
                      <td colSpan={COLUMNS.length}>
                        <div className="device-detail">
                          <div className="detail-grid">
                            <div className="detail-item">
                              <span className="detail-label">IP-адрес:</span>
                              <span className="detail-value">{device.ip}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">MAC:</span>
                              <span className="detail-value">{device.mac || '—'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Подсеть:</span>
                              <span className="detail-value">{device.subnet || '—'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Тип:</span>
                              <span className="detail-value" style={{ color: typeColor }}>{TYPE_LABELS[device.type] || 'Неизвестно'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Вендор:</span>
                              <span className="detail-value">{device.vendor || '—'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">ОС:</span>
                              <span className="detail-value">{device.os_guess || '—'}</span>
                            </div>
                            {hw.cpu_model && (
                              <div className="detail-item">
                                <span className="detail-label">CPU:</span>
                                <span className="detail-value">{hw.cpu_model} ({hw.cpu_cores} ядра)</span>
                              </div>
                            )}
                            {hw.ram_total_gb && (
                              <div className="detail-item">
                                <span className="detail-label">RAM:</span>
                                <span className="detail-value">{hw.ram_used_gb || '?'} / {hw.ram_total_gb} ГБ</span>
                              </div>
                            )}
                            {hw.disk_total_gb && (
                              <div className="detail-item">
                                <span className="detail-label">Диск:</span>
                                <span className="detail-value">{hw.disk_used_gb || '?'} / {hw.disk_total_gb} ГБ</span>
                              </div>
                            )}
                            {hw.uptime_hours != null && (
                              <div className="detail-item">
                                <span className="detail-label">Аптайм:</span>
                                <span className="detail-value">{Math.round(hw.uptime_hours)}ч</span>
                              </div>
                            )}
                            <div className="detail-item">
                              <span className="detail-label">Группа:</span>
                              <span className="detail-value">{device.group_id || '—'}</span>
                            </div>
                          </div>

                          {portsCount > 0 && (
                            <div className="detail-ports">
                              <h4>Открытые порты ({portsCount})</h4>
                              <table className="ports-table">
                                <thead>
                                  <tr>
                                    <th>Порт</th>
                                    <th>Протокол</th>
                                    <th>Сервис</th>
                                    <th>Версия</th>
                                    <th>Статус</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {device.ports.map((port, i) => (
                                    <tr key={i}>
                                      <td>{port.port}</td>
                                      <td>{port.protocol}</td>
                                      <td>{port.service || '—'}</td>
                                      <td>{port.version || '—'}</td>
                                      <td><span className={`port-status ${port.state}`}>{port.state}</span></td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
            {paged.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length} className="empty-state">
                  Устройства не найдены
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button
            className="page-btn"
            disabled={page === 0}
            onClick={() => setPage(p => p - 1)}
          >
            <ChevronLeft size={16} />
          </button>
          <span className="page-info">
            Страница {page + 1} из {totalPages}
          </span>
          <button
            className="page-btn"
            disabled={page >= totalPages - 1}
            onClick={() => setPage(p => p + 1)}
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}
    </div>
  )
}
