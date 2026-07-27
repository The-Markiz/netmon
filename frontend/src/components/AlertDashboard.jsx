import React, { useState, useMemo } from 'react'
import { AlertTriangle, AlertCircle, Info, CheckCircle, Filter, ChevronDown, ChevronUp, Bell, BellOff } from 'lucide-react'

const SEVERITY_CONFIG = {
  critical: { label: 'Критический', color: '#ef4444', icon: AlertTriangle, className: 'severity-critical' },
  warning: { label: 'Предупреждение', color: '#f59e0b', icon: AlertCircle, className: 'severity-warning' },
  info: { label: 'Информация', color: '#3b82f6', icon: Info, className: 'severity-info' },
}

const ALERT_TYPES = {
  new_device: 'Новое устройство',
  device_offline: 'Устройство оффлайн',
  port_scan: 'Сканирование портов',
  high_traffic: 'Высокий трафик',
  unauthorized_device: 'Неавторизованное устройство',
  configuration_change: 'Изменение конфигурации',
  security_event: 'Событие безопасности',
}

export default function AlertDashboard({ alerts, onAcknowledge }) {
  const [severityFilter, setSeverityFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')
  const [ackFilter, setAckFilter] = useState('all')
  const [expandedId, setExpandedId] = useState(null)
  const [sortNewest, setSortNewest] = useState(true)

  const filtered = useMemo(() => {
    let result = [...alerts]

    if (severityFilter !== 'all') {
      result = result.filter(a => a.severity === severityFilter)
    }

    if (typeFilter !== 'all') {
      result = result.filter(a => a.alert_type === typeFilter)
    }

    if (ackFilter === 'acknowledged') {
      result = result.filter(a => a.acknowledged === 1 || a.acknowledged === true)
    } else if (ackFilter === 'unacknowledged') {
      result = result.filter(a => a.acknowledged !== 1 && a.acknowledged !== true)
    }

    result.sort((a, b) => {
      const da = new Date(a.timestamp || a.created_at || 0)
      const db = new Date(b.timestamp || b.created_at || 0)
      return sortNewest ? db - da : da - db
    })

    return result
  }, [alerts, severityFilter, typeFilter, ackFilter, sortNewest])

  const usedTypes = useMemo(() => {
    const types = new Set(alerts.map(a => a.alert_type).filter(Boolean))
    return Array.from(types)
  }, [alerts])

  const criticalCount = alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length
  const warningCount = alerts.filter(a => a.severity === 'warning' && !a.acknowledged).length

  return (
    <div className="alert-dashboard">
      <div className="alert-toolbar">
        <div className="filter-group">
          <Filter size={16} />
          <label>Серьёзность:</label>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="all">Все</option>
            <option value="critical">Критический</option>
            <option value="warning">Предупреждение</option>
            <option value="info">Информация</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Тип:</label>
          <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="all">Все типы</option>
            {usedTypes.map(t => (
              <option key={t} value={t}>{ALERT_TYPES[t] || t}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label>Статус:</label>
          <select value={ackFilter} onChange={e => setAckFilter(e.target.value)}>
            <option value="all">Все</option>
            <option value="unacknowledged">Не подтверждённые</option>
            <option value="acknowledged">Подтверждённые</option>
          </select>
        </div>

        <button
          className={`sort-btn ${sortNewest ? 'active' : ''}`}
          onClick={() => setSortNewest(!sortNewest)}
        >
          {sortNewest ? 'Новые первыми' : 'Старые первыми'}
        </button>

        <div className="alert-summary">
          {criticalCount > 0 && (
            <span className="summary-badge critical">{criticalCount} критических</span>
          )}
          {warningCount > 0 && (
            <span className="summary-badge warning">{warningCount} предупреждений</span>
          )}
        </div>
      </div>

      <div className="alert-list">
        {filtered.length === 0 && (
          <div className="empty-state">
            <BellOff size={48} />
            <p>Алерты не найдены</p>
          </div>
        )}

        {filtered.map((alert, idx) => {
          const config = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.info
          const Icon = config.icon
          const expanded = expandedId === alert.id
          const isAcknowledged = alert.acknowledged === 1 || alert.acknowledged === true
          const isNew = idx < 3 && sortNewest
          const typeLabel = ALERT_TYPES[alert.alert_type] || alert.alert_type || 'Неизвестный тип'

          return (
            <div
              key={alert.id || idx}
              className={`alert-card ${config.className} ${isAcknowledged ? 'acknowledged' : ''} ${isNew ? 'new-alert' : ''}`}
            >
              <div className="alert-card-header" onClick={() => setExpandedId(expanded ? null : alert.id)}>
                <div className="alert-severity-icon" style={{ backgroundColor: config.color + '22', color: config.color }}>
                  <Icon size={20} />
                </div>

                <div className="alert-card-info">
                  <div className="alert-card-title">
                    {alert.title || alert.message || typeLabel}
                  </div>
                  <div className="alert-card-meta">
                    <span className="alert-type">{typeLabel}</span>
                    <span className="alert-time">
                      {alert.timestamp || alert.created_at
                        ? new Date(alert.timestamp || alert.created_at).toLocaleString('ru-RU')
                        : '—'}
                    </span>
                    {alert.device_ip && (
                      <span className="alert-device">Устройство: {alert.device_ip}</span>
                    )}
                  </div>
                </div>

                <div className="alert-card-actions">
                  {!isAcknowledged && (
                    <button
                      className="ack-btn"
                      onClick={(e) => {
                        e.stopPropagation()
                        onAcknowledge(alert.id)
                      }}
                      title="Подтвердить"
                    >
                      <CheckCircle size={18} />
                      <span>Подтвердить</span>
                    </button>
                  )}
                  {isAcknowledged && (
                    <span className="ack-badge">
                      <CheckCircle size={14} />
                      Подтверждено
                    </span>
                  )}
                  {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                </div>
              </div>

              {expanded && (
                <div className="alert-card-detail">
                  <div className="detail-section">
                    <h4>Детали алерта</h4>
                    <div className="detail-grid">
                      <div className="detail-item">
                        <span className="detail-label">ID:</span>
                        <span className="detail-value">{alert.id}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Серьёзность:</span>
                        <span className="detail-value" style={{ color: config.color }}>{config.label}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Тип:</span>
                        <span className="detail-value">{typeLabel}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Устройство:</span>
                        <span className="detail-value">{alert.device_ip || '—'}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">Создан:</span>
                        <span className="detail-value">
                          {alert.timestamp || alert.created_at
                            ? new Date(alert.timestamp || alert.created_at).toLocaleString('ru-RU')
                            : '—'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {alert.description && (
                    <div className="detail-section">
                      <h4>Описание</h4>
                      <p className="alert-description">{alert.description}</p>
                    </div>
                  )}

                  {alert.details_json && (
                    <div className="detail-section">
                      <h4>Дополнительная информация</h4>
                      <pre className="alert-details-json">
                        {(() => {
                          try {
                            const parsed = typeof alert.details_json === 'string'
                              ? JSON.parse(alert.details_json)
                              : alert.details_json
                            return JSON.stringify(parsed, null, 2)
                          } catch {
                            return alert.details_json
                          }
                        })()}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
