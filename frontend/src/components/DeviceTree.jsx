import React, { useState, useEffect, useCallback } from 'react'
import { FolderTree, Folder, FolderOpen, Server, Monitor, Wifi, HelpCircle, ChevronRight, ChevronDown, Plus, X, Check, GripVertical } from 'lucide-react'

const TYPE_ICONS = {
  router: Server, server: Server, pc: Monitor, switch: Wifi, iot: HelpCircle, phone: HelpCircle, unknown: HelpCircle,
}
const TYPE_COLORS = {
  router: '#f59e0b', server: '#3b82f6', pc: '#10b981', switch: '#8b5cf6', iot: '#ec4899', phone: '#06b6d4', unknown: '#64748b',
}

export default function DeviceTree({ devices, onSelectDevice, selectedDevice }) {
  const [groups, setGroups] = useState([])
  const [expanded, setExpanded] = useState({})
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [assigning, setAssigning] = useState(null) // { deviceId, groupId }
  const [editingGroup, setEditingGroup] = useState(null)

  const fetchGroups = useCallback(async () => {
    try {
      const res = await fetch('/api/groups')
      if (res.ok) {
        const data = await res.json()
        setGroups(data.groups || data || [])
      }
    } catch (e) {
      console.error('Failed to fetch groups:', e)
    }
  }, [])

  useEffect(() => { fetchGroups() }, [fetchGroups])

  const createGroup = async () => {
    if (!newName.trim()) return
    try {
      const res = await fetch('/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName.trim() }),
      })
      if (res.ok) {
        setNewName('')
        setShowCreate(false)
        fetchGroups()
      }
    } catch (e) {
      console.error('Failed to create group:', e)
    }
  }

  const deleteGroup = async (id) => {
    if (!confirm('Удалить группу? Устройства останутся без группы.')) return
    try {
      const res = await fetch(`/api/groups/${id}`, { method: 'DELETE' })
      if (res.ok) {
        fetchGroups()
      }
    } catch (e) {
      console.error('Failed to delete group:', e)
    }
  }

  const renameGroup = async (id, name) => {
    try {
      const res = await fetch(`/api/groups/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      })
      if (res.ok) {
        setEditingGroup(null)
        fetchGroups()
      }
    } catch (e) {
      console.error('Failed to rename group:', e)
    }
  }

  const assignDevice = async (deviceId, groupId) => {
    try {
      const res = await fetch(`/api/devices/${deviceId}/group`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId }),
      })
      if (res.ok) {
        setAssigning(null)
        // update local devices
        onSelectDevice(null)
      }
    } catch (e) {
      console.error('Failed to assign device:', e)
    }
  }

  const toggleExpand = (key) => setExpanded(prev => ({ ...prev, [key]: !prev[key] }))

  const groupedDevices = groups.map(g => ({
    ...g,
    devices: devices.filter(d => d.group_id === g.id),
  }))
  const ungrouped = devices.filter(d => !d.group_id)

  return (
    <div className="device-tree">
      <div className="tree-toolbar">
        <h2 className="tree-title"><FolderTree size={18} /> Дерево устройств</h2>
        <button className="add-btn" onClick={() => setShowCreate(true)}>
          <Plus size={14} /> Группа
        </button>
      </div>

      {showCreate && (
        <div className="tree-create-row">
          <input
            autoFocus
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && createGroup()}
            placeholder="Название группы..."
            className="tree-create-input"
          />
          <button className="icon-btn" onClick={createGroup} style={{ background: 'var(--green-dim)', color: 'var(--green)' }}><Check size={14} /></button>
          <button className="icon-btn" onClick={() => { setShowCreate(false); setNewName('') }}><X size={14} /></button>
        </div>
      )}

      <div className="tree-body">
        {groupedDevices.map(group => (
          <div key={group.id} className="tree-group" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); const id = parseInt(e.dataTransfer.getData('deviceId')); if (id) assignDevice(id, group.id) }}>
            <div className="tree-group-header" onClick={() => toggleExpand(`g-${group.id}`)}>
              {expanded[`g-${group.id}`] ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
              {expanded[`g-${group.id}`] ? <FolderOpen size={16} className="tree-folder-icon" /> : <Folder size={16} className="tree-folder-icon" />}
              {editingGroup === group.id ? (
                <input
                  autoFocus
                  defaultValue={group.name}
                  onClick={e => e.stopPropagation()}
                  onKeyDown={e => {
                    if (e.key === 'Enter') renameGroup(group.id, e.target.value)
                    if (e.key === 'Escape') setEditingGroup(null)
                  }}
                  onBlur={e => renameGroup(group.id, e.target.value)}
                  className="tree-rename-input"
                />
              ) : (
                <span className="tree-group-name" onDoubleClick={e => { e.stopPropagation(); setEditingGroup(group.id) }}>{group.name}</span>
              )}
              <span className="tree-count">{group.devices.length}</span>
              <button className="icon-btn" onClick={e => { e.stopPropagation(); deleteGroup(group.id) }} title="Удалить группу" style={{ marginLeft: 'auto' }}><X size={12} /></button>
            </div>
            {expanded[`g-${group.id}`] && (
              <div className="tree-group-devices">
                {group.devices.length === 0 && <div className="tree-empty">Нет устройств</div>}
                {group.devices.map(d => (
                  <DeviceNode key={d.id} device={d} selected={selectedDevice?.id === d.id} onSelect={onSelectDevice} />
                ))}
              </div>
            )}
          </div>
        ))}

        <div className="tree-group" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); const id = parseInt(e.dataTransfer.getData('deviceId')); if (id) assignDevice(id, null) }}>
          <div className="tree-group-header" onClick={() => toggleExpand('ungrouped')}>
            {expanded['ungrouped'] ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
            <Folder size={16} style={{ color: 'var(--text-dim)' }} />
            <span className="tree-group-name">Без группы</span>
            <span className="tree-count">{ungrouped.length}</span>
          </div>
          {expanded['ungrouped'] && (
            <div className="tree-group-devices">
              {ungrouped.length === 0 && <div className="tree-empty">Все устройства в группах</div>}
              {ungrouped.map(d => (
                <DeviceNode key={d.id} device={d} selected={selectedDevice?.id === d.id} onSelect={onSelectDevice} />
              ))}
            </div>
          )}
        </div>
      </div>

      {assigning && (
        <div className="tree-assign-modal" onClick={() => setAssigning(null)}>
          <div className="tree-assign-dialog" onClick={e => e.stopPropagation()}>
            <h3>Назначить группу</h3>
            {groups.map(g => (
              <button key={g.id} className="tree-assign-option" onClick={() => { assignDevice(assigning.deviceId, g.id); setAssigning(null) }}>
                <Folder size={14} /> {g.name}
              </button>
            ))}
            <button className="tree-assign-option" onClick={() => { assignDevice(assigning.deviceId, null); setAssigning(null) }} style={{ color: 'var(--text-dim)' }}>
              <X size={14} /> Без группы
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function DeviceNode({ device, selected, onSelect }) {
  const Icon = TYPE_ICONS[device.type] || HelpCircle
  const color = TYPE_COLORS[device.type] || TYPE_COLORS.unknown

  return (
    <div
      className={`tree-device ${selected ? 'selected' : ''} ${device.status === 'online' ? '' : 'offline'}`}
      onClick={() => onSelect(device)}
      draggable
      onDragStart={e => e.dataTransfer.setData('deviceId', String(device.id))}
    >
      <span className="tree-device-dot" style={{ background: device.status === 'online' ? 'var(--green)' : 'var(--red)' }} />
      <Icon size={14} style={{ color, flexShrink: 0 }} />
      <span className="tree-device-name">{device.hostname || device.ip}</span>
      <span className="tree-device-ip">{device.ip}</span>
    </div>
  )
}
