import React, { useState, useEffect } from 'react'
import { Save, RefreshCw, Plus, Trash2, ChevronUp, ChevronDown, Layout, Shield, Wifi, Download, Radar } from 'lucide-react'

const API_BASE = '/api'

const WIDGET_TYPES = {
  stats_summary: { label: 'Сводка статистики', icon: '📊' },
  alerts_list: { label: 'Последние алерты', icon: '🔔' },
  recent_devices: { label: 'Новые устройства', icon: '💻' },
  scan_status: { label: 'Статус сканирования', icon: '🔍' },
}

const DEFAULT_DASHBOARD = [
  { id: 'w1', type: 'stats_summary', title: 'Сводка статистики', enabled: true },
  { id: 'w2', type: 'alerts_list', title: 'Последние алерты', enabled: true },
  { id: 'w3', type: 'recent_devices', title: 'Новые устройства', enabled: true },
  { id: 'w4', type: 'scan_status', title: 'Статус сканирования', enabled: true },
]

const RULE_LABELS = {
  new_device: { name: 'Новое устройство', description: 'Уведомлять о новых устройствах в сети' },
  device_offline: { name: 'Устройство оффлайн', description: 'Уведомлять когда устройство недоступно' },
  device_online: { name: 'Устройство вернулось', description: 'Уведомлять когда устройство снова доступно' },
  port_opened: { name: 'Открыт порт', description: 'Уведомлять об открытии нового порта' },
  port_closed: { name: 'Закрыт порт', description: 'Уведомлять о закрытии порта' },
}

export default function Settings({ config, onSave }) {
  const [dashboard, setDashboard] = useState([])
  const [rules, setRules] = useState({})
  const [scanConfig, setScanConfig] = useState({ interval: 30, subnet: '', subnets: [] })
  const [scannerModules, setScannerModules] = useState([])
  const [saved, setSaved] = useState(false)
  const [addWidgetType, setAddWidgetType] = useState('stats_summary')
  const [scannerSaving, setScannerSaving] = useState(false)
  const [scannerMsg, setScannerMsg] = useState('')
  const [rulesSaving, setRulesSaving] = useState(false)
  const [rulesMsg, setRulesMsg] = useState('')

  useEffect(() => {
    if (config) {
      setDashboard(config.dashboard || DEFAULT_DASHBOARD)
    } else {
      setDashboard(DEFAULT_DASHBOARD)
    }
  }, [config])

  useEffect(() => {
    fetch(`${API_BASE}/scanner/config`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data) {
          setScanConfig({
            interval: data.interval || 30,
            subnet: data.subnet || '',
            subnets: data.subnets || [],
          })
        }
      })
      .catch(() => {})

    fetch(`${API_BASE}/scanner/modules`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.modules) {
          setScannerModules(data.modules)
        }
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetch(`${API_BASE}/alerts/rules`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.rules) {
          setRules(data.rules)
        }
      })
      .catch(() => {})
  }, [])

  const handleSave = () => {
    onSave({ dashboard })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleSaveScanner = async () => {
    setScannerSaving(true)
    setScannerMsg('')
    try {
      const res = await fetch(`${API_BASE}/scanner/config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interval: scanConfig.interval,
          subnet: scanConfig.subnet || undefined,
        }),
      })
      if (res.ok) {
        setScannerMsg('Настройки сканера сохранены!')
      } else {
        const err = await res.json()
        setScannerMsg(err.detail || 'Ошибка сохранения')
      }
    } catch (e) {
      setScannerMsg('Ошибка сети')
    }
    setScannerSaving(false)
    setTimeout(() => setScannerMsg(''), 3000)
  }

  const handleToggleRule = async (ruleName) => {
    const currentEnabled = rules[ruleName]?.enabled ?? true
    const newEnabled = !currentEnabled

    setRules(prev => ({
      ...prev,
      [ruleName]: { ...prev[ruleName], enabled: newEnabled },
    }))

    setRulesSaving(true)
    try {
      const res = await fetch(`${API_BASE}/alerts/rules/${ruleName}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newEnabled }),
      })
      if (res.ok) {
        setRulesMsg('Правило обновлено')
      } else {
        setRules(prev => ({
          ...prev,
          [ruleName]: { ...prev[ruleName], enabled: currentEnabled },
        }))
        setRulesMsg('Ошибка')
      }
    } catch (e) {
      setRules(prev => ({
        ...prev,
        [ruleName]: { ...prev[ruleName], enabled: currentEnabled },
      }))
      setRulesMsg('Ошибка сети')
    }
    setRulesSaving(false)
    setTimeout(() => setRulesMsg(''), 2000)
  }

  const handleToggleScanner = async (moduleName) => {
    try {
      const res = await fetch(`${API_BASE}/scanner/modules/${moduleName}/toggle`, { method: 'PUT' })
      if (res.ok) {
        const data = await res.json()
        setScannerModules(prev =>
          prev.map(m => m.name === moduleName ? { ...m, enabled: data.enabled } : m)
        )
      }
    } catch (e) {
      console.error('Failed to toggle scanner:', e)
    }
  }

  const handleExportCSV = () => {
    window.open(`${API_BASE}/export/devices`, '_blank')
  }

  const moveWidget = (index, direction) => {
    const newDash = [...dashboard]
    const targetIndex = index + direction
    if (targetIndex < 0 || targetIndex >= newDash.length) return
    const temp = newDash[index]
    newDash[index] = newDash[targetIndex]
    newDash[targetIndex] = temp
    setDashboard(newDash)
  }

  const addWidget = () => {
    const type = addWidgetType
    const newWidget = {
      id: `w_${Date.now()}`,
      type,
      title: WIDGET_TYPES[type].label,
      enabled: true,
    }
    setDashboard([...dashboard, newWidget])
  }

  const removeWidget = (id) => {
    setDashboard(dashboard.filter(w => w.id !== id))
  }

  const toggleWidget = (id) => {
    setDashboard(dashboard.map(w => w.id === id ? { ...w, enabled: !w.enabled } : w))
  }

  return (
    <div className="settings">
      <div className="settings-header">
        <h2>Настройки</h2>
        <div className="header-actions">
          <button className="export-btn" onClick={handleExportCSV}>
            <Download size={16} />
            Экспорт CSV
          </button>
          <button className={`save-btn ${saved ? 'saved' : ''}`} onClick={handleSave}>
            {saved ? (
              <>
                <RefreshCw size={16} className="spin" />
                Сохранено!
              </>
            ) : (
              <>
                <Save size={16} />
                Сохранить настройки
              </>
            )}
          </button>
        </div>
      </div>

      <div className="settings-grid">
        <section className="settings-section">
          <h3 className="section-title">
            <Wifi size={20} />
            Настройки сканера
          </h3>

          <div className="form-grid">
            <div className="form-field">
              <label>Интервал сканирования (секунды):</label>
              <input
                type="number"
                min={10}
                max={86400}
                value={scanConfig.interval}
                onChange={e => setScanConfig({ ...scanConfig, interval: parseInt(e.target.value) || 30 })}
              />
              <span className="form-hint">Минимум 10 секунд. Автосканирование будет выполняться каждые {scanConfig.interval}с.</span>
            </div>

            {scanConfig.subnets && scanConfig.subnets.length > 0 && (
              <div className="detected-subnets">
                <label>Обнаруженные подсети ({scanConfig.subnets.length}):</label>
                <div className="subnet-list">
                  {scanConfig.subnets.map((s, i) => (
                    <div key={i} className="subnet-item">
                      <span className={`subnet-badge ${i === 0 ? 'primary' : ''}`}>{s.subnet}</span>
                      <span className="subnet-gw">шлюз: {s.gateway}</span>
                      <span className="subnet-iface">{s.interface}</span>
                    </div>
                  ))}
                </div>
                <span className="form-hint">Все подсети будут сканироваться автоматически.</span>
              </div>
            )}

            <div className="form-field">
              <label>Ручная подсеть (переопределение):</label>
              <input
                type="text"
                value={scanConfig.subnet}
                onChange={e => setScanConfig({ ...scanConfig, subnet: e.target.value })}
                placeholder="Автоопределение всех подсетей (оставьте пустым)"
              />
              <span className="form-hint">CIDR формат. Если задано — сканируется только эта подсеть. Если пусто — авто-определение всех локальных подсетей.</span>
            </div>
          </div>

          <div className="scanner-actions">
            <button
              className={`save-scanner-btn ${scannerSaving ? 'saving' : ''}`}
              onClick={handleSaveScanner}
              disabled={scannerSaving}
            >
              {scannerSaving ? <RefreshCw size={14} className="spin" /> : <Save size={14} />}
              Применить к сканеру
            </button>
            {scannerMsg && (
              <span className={`scanner-msg ${scannerMsg.includes('Ошибка') ? 'error' : 'ok'}`}>
                {scannerMsg}
              </span>
            )}
          </div>
        </section>

        <section className="settings-section">
          <h3 className="section-title">
            <Radar size={20} />
            Модули сканеров
          </h3>
          <p className="section-desc">Включите или отключите дополнительные методы сбора информации об устройствах.</p>

          <div className="scanner-modules-list">
            {scannerModules.map(module => (
              <div key={module.name} className={`scanner-module-item ${module.enabled ? '' : 'disabled'}`}>
                <div className="scanner-module-info">
                  <span className="scanner-module-name">{module.name.toUpperCase()}</span>
                  <span className="scanner-module-desc">{module.description}</span>
                  {module.requires_nmap && <span className="scanner-module-tag">nmap</span>}
                  {module.requires_root && <span className="scanner-module-tag root">root</span>}
                </div>
                <button
                  className={`toggle-btn ${module.enabled ? 'on' : 'off'}`}
                  onClick={() => handleToggleScanner(module.name)}
                >
                  <span className="toggle-knob" />
                  <span className="toggle-label">{module.enabled ? 'Вкл' : 'Выкл'}</span>
                </button>
              </div>
            ))}
          </div>
        </section>

        <section className="settings-section">
          <h3 className="section-title">
            <Layout size={20} />
            Панели дашборда
          </h3>
          <p className="section-desc">Настройте виджеты на главной странице. Используйте кнопки для перемещения.</p>

          <div className="widget-list">
            {dashboard.map((widget, idx) => (
              <div key={widget.id} className={`widget-item ${widget.enabled ? '' : 'disabled'}`}>
                <div className="widget-info">
                  <span className="widget-icon">{WIDGET_TYPES[widget.type]?.icon || '📋'}</span>
                  <span className="widget-name">{widget.title}</span>
                  <span className="widget-type">({WIDGET_TYPES[widget.type]?.label || widget.type})</span>
                </div>
                <div className="widget-actions">
                  <button
                    className="icon-btn"
                    onClick={() => moveWidget(idx, -1)}
                    disabled={idx === 0}
                    title="Вверх"
                  >
                    <ChevronUp size={16} />
                  </button>
                  <button
                    className="icon-btn"
                    onClick={() => moveWidget(idx, 1)}
                    disabled={idx === dashboard.length - 1}
                    title="Вниз"
                  >
                    <ChevronDown size={16} />
                  </button>
                  <button
                    className={`icon-btn toggle ${widget.enabled ? 'on' : 'off'}`}
                    onClick={() => toggleWidget(widget.id)}
                    title={widget.enabled ? 'Выключить' : 'Включить'}
                  >
                    {widget.enabled ? '✓' : '✗'}
                  </button>
                  <button
                    className="icon-btn danger"
                    onClick={() => removeWidget(widget.id)}
                    title="Удалить"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="add-widget">
            <select value={addWidgetType} onChange={e => setAddWidgetType(e.target.value)}>
              {Object.entries(WIDGET_TYPES).map(([key, val]) => (
                <option key={key} value={key}>{val.icon} {val.label}</option>
              ))}
            </select>
            <button className="add-btn" onClick={addWidget}>
              <Plus size={16} />
              Добавить виджет
            </button>
          </div>
        </section>

        <section className="settings-section">
          <h3 className="section-title">
            <Shield size={20} />
            Правила алертов
          </h3>
          <p className="section-desc">Включите или отключите правила уведомлений. Изменения применяются сразу.</p>

          <div className="rules-list">
            {Object.entries(rules).map(([ruleName, rule]) => {
              const label = RULE_LABELS[ruleName] || { name: ruleName, description: '' }
              return (
                <div key={ruleName} className={`rule-item ${rule.enabled ? 'enabled' : 'disabled'}`}>
                  <div className="rule-info">
                    <span className="rule-name">{label.name}</span>
                    <span className="rule-desc">{label.description}</span>
                  </div>
                  <button
                    className={`toggle-btn ${rule.enabled ? 'on' : 'off'}`}
                    onClick={() => handleToggleRule(ruleName)}
                    disabled={rulesSaving}
                  >
                    <span className="toggle-knob" />
                    <span className="toggle-label">{rule.enabled ? 'Вкл' : 'Выкл'}</span>
                  </button>
                </div>
              )
            })}
            {Object.keys(rules).length === 0 && (
              <div className="empty-state">Загрузка правил...</div>
            )}
          </div>

          {rulesMsg && (
            <div className={`scanner-msg ${rulesMsg.includes('Ошибка') ? 'error' : 'ok'}`} style={{ marginTop: 12 }}>
              {rulesMsg}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
