import React, { useEffect, useState, useRef } from 'react'
import { Monitor, Wifi, WifiOff, AlertTriangle, AlertCircle, Info } from 'lucide-react'

function AnimatedCounter({ value, duration = 600 }) {
  const [display, setDisplay] = useState(0)
  const prevRef = useRef(0)

  useEffect(() => {
    const start = prevRef.current
    const end = value
    const diff = end - start
    if (diff === 0) return

    const startTime = performance.now()
    function tick(now) {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(start + diff * eased))
      if (progress < 1) {
        requestAnimationFrame(tick)
      } else {
        prevRef.current = end
      }
    }
    requestAnimationFrame(tick)
  }, [value, duration])

  return <span className="counter-value">{display}</span>
}

export default function StatsBar({ stats }) {
  return (
    <div className="stats-bar">
      <div className="stat-card">
        <div className="stat-card-icon total">
          <Monitor size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Всего устройств</span>
          <AnimatedCounter value={stats.total} />
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-card-icon online">
          <Wifi size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Онлайн</span>
          <AnimatedCounter value={stats.online} />
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-card-icon offline">
          <WifiOff size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Оффлайн</span>
          <AnimatedCounter value={stats.offline} />
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-card-icon critical">
          <AlertTriangle size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Критические</span>
          <AnimatedCounter value={stats.alerts.critical} />
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-card-icon warning">
          <AlertCircle size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Предупреждения</span>
          <AnimatedCounter value={stats.alerts.warning} />
        </div>
      </div>

      <div className="stat-card">
        <div className="stat-card-icon info">
          <Info size={20} />
        </div>
        <div className="stat-card-info">
          <span className="stat-card-label">Инфо</span>
          <AnimatedCounter value={stats.alerts.info} />
        </div>
      </div>
    </div>
  )
}
