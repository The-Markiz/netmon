import React from 'react'
import { Network, Monitor, Bell, Settings, Wifi, WifiOff, FolderTree, FileText, Radio } from 'lucide-react'

const navItems = [
  { path: '/', label: 'Карта сети', icon: Network },
  { path: '/devices', label: 'Устройства', icon: Monitor },
  { path: '/tree', label: 'Дерево', icon: FolderTree },
  { path: '/wifi', label: 'WiFi', icon: Radio },
  { path: '/alerts', label: 'Алерты', icon: Bell },
  { path: '/reports', label: 'Отчёты', icon: FileText },
  { path: '/settings', label: 'Настройки', icon: Settings },
]

export default function Sidebar({ route, onNavigate, connected, onlineCount, offlineCount, totalCount, alertCount }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="logo">
          <Network size={28} />
          <div>
            <h1 className="logo-title">NetMon</h1>
            <span className="logo-subtitle">Мониторинг сети</span>
          </div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map(item => {
          const Icon = item.icon
          const active = route === item.path
          return (
            <button
              key={item.path}
              className={`nav-item ${active ? 'active' : ''}`}
              onClick={() => onNavigate(item.path)}
            >
              <Icon size={20} />
              <span>{item.label}</span>
              {item.path === '/alerts' && alertCount > 0 && (
                <span className="nav-badge">{alertCount > 99 ? '99+' : alertCount}</span>
              )}
            </button>
          )
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="connection-status">
          {connected ? (
            <>
              <Wifi size={16} className="status-icon connected" />
              <span className="status-text connected">WebSocket подключен</span>
            </>
          ) : (
            <>
              <WifiOff size={16} className="status-icon disconnected" />
              <span className="status-text disconnected">WebSocket отключен</span>
            </>
          )}
        </div>

        <div className="quick-stats">
          <div className="quick-stat">
            <span className="stat-label">Устройства:</span>
            <span className="stat-value">
              <span className="stat-online">{onlineCount}</span>
              {' / '}
              <span className="stat-total">{totalCount}</span>
            </span>
          </div>
          <div className="quick-stat">
            <span className="stat-label">Оффлайн:</span>
            <span className="stat-value stat-offline">{offlineCount}</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
