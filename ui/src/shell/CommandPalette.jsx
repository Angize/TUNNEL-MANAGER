import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Icon from '../components/Icon.jsx'
import { T } from '../i18n/fa.js'
import { apiGet } from '../lib/api.js'
import { setPageQuery } from '../lib/pageQuery.js'
import { runCommand } from '../lib/pageCommand.js'

const LIMIT = 6

export default function CommandPalette({ dark, onNavigate, onToggleTheme, onClose }) {
  const [text, setText] = useState('')
  const [nodes, setNodes] = useState([])
  const [links, setLinks] = useState([])
  const [index, setIndex] = useState(0)
  const list = useRef(null)
  const input = useRef(null)

  useEffect(() => {
    let alive = true
    apiGet('node-names')
      .then((r) => alive && setNodes(r.nodes))
      .catch(() => {})
    apiGet('fleet')
      .then((r) => alive && setLinks(r.links))
      .catch(() => {})
    if (input.current) input.current.focus()
    return () => {
      alive = false
    }
  }, [])

  const goto = useCallback(
    (page, before) => {
      onClose()
      onNavigate(page, before)
    },
    [onClose, onNavigate]
  )

  const actions = useMemo(
    () => [
      { i: 'dash', label: T('nav_overview'), act: () => goto('overview') },
      { i: 'server', label: T('nav_nodes'), act: () => goto('nodes') },
      { i: 'globe', label: T('nav_fleet') + ' · ' + T('nav_proxies'), act: () => goto('proxies') },
      { i: 'link', label: T('nav_links') + ' · ' + T('nav_core'), act: () => goto('core') },
      { i: 'link', label: T('nav_links') + ' · ' + T('nav_tunnels'), act: () => goto('tunnels') },
      { i: 'link', label: T('nav_links') + ' · ' + T('nav_portfw'), act: () => goto('portfw') },
      { i: 'list', label: T('nav_logs'), act: () => goto('logs') },
      { i: 'cog', label: T('nav_settings'), act: () => goto('settings') },
      {
        i: 'plus',
        label: T('pal_add_core'),
        act: () => goto('core', () => runCommand('core:create')),
      },
      {
        i: 'plus',
        label: T('pal_add_tun'),
        act: () => goto('tunnels', () => runCommand('tunnels:create')),
      },
      { i: 'redo', label: T('pal_agent'), act: () => goto('set-upkeep') },
      {
        i: 'activity',
        label: T('pal_checkall_core'),
        act: () => goto('core', () => runCommand('core:checkall')),
      },
      {
        i: 'activity',
        label: T('pal_checkall'),
        act: () => goto('tunnels', () => runCommand('tunnels:checkall')),
      },
      {
        i: dark ? 'sun' : 'moon',
        label: T('pal_theme'),
        act: () => {
          onClose()
          onToggleTheme()
        },
      },
    ],
    [dark, goto, onClose, onToggleTheme]
  )

  const groups = useMemo(() => {
    const q = text.trim().toLowerCase()
    const nodeRows = nodes
      .filter((n) => !q || n.name.toLowerCase().includes(q) || (n.host || '').includes(q))
      .slice(0, LIMIT)
      .map((n) => ({
        i: 'server',
        label: n.name,
        sub: n.host,
        act: () => goto('nodes', () => setPageQuery('nodes', '"' + n.name + '"')),
      }))
    const linkRows = links
      .filter(
        (l) =>
          !q ||
          ((l.a_name || '') + ' ' + (l.b_name || '') + ' ' + (l.name || '') + ' ' + (l.type || ''))
            .toLowerCase()
            .includes(q)
      )
      .slice(0, LIMIT)
      .map((l) => ({
        i: 'link',
        label: l.a_name + ' ↔ ' + l.b_name,
        sub: l.name,
        act: () => {
          const page = l.type === 'core' ? 'core' : 'tunnels'
          goto(page, () => setPageQuery(page, '"' + l.name + '"'))
        },
      }))
    const actionRows = actions.filter((a) => !q || a.label.toLowerCase().includes(q))
    return [
      [T('pal_g_nodes'), nodeRows],
      [T('pal_g_tuns'), linkRows],
      [T('pal_g_acts'), actionRows],
    ].filter((g) => g[1].length)
  }, [text, nodes, links, actions, goto])

  const items = useMemo(() => groups.flatMap((g) => g[1]), [groups])

  useEffect(() => {
    setIndex(0)
  }, [text, nodes, links])

  useEffect(() => {
    const rows = list.current ? list.current.querySelectorAll('.palrow') : []
    const row = rows[index]
    if (row) row.scrollIntoView({ block: 'nearest' })
  }, [index])

  const onKey = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIndex((i) => Math.min(i + 1, items.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIndex((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const item = items[index]
      if (item) item.act()
    } else if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    }
  }

  let cursor = -1

  return (
    <div
      className="modalov palov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="pal">
        <div className="palin">
          <Icon name="search" />
          <input
            ref={input}
            placeholder={T('pal_search')}
            autoComplete="off"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKey}
          />
          <kbd>Esc</kbd>
        </div>
        <div className="pallist" ref={list}>
          {items.length ? (
            groups.map(([title, rows]) => (
              <div key={title}>
                <div className="palsec">{title}</div>
                {rows.map((row) => {
                  cursor += 1
                  const at = cursor
                  return (
                    <div
                      key={title + ':' + row.label + ':' + at}
                      className={'palrow' + (at === index ? ' sel' : '')}
                      onMouseEnter={() => setIndex(at)}
                      onClick={row.act}
                    >
                      <span className="gi">
                        <Icon name={row.i} />
                      </span>
                      {row.label}
                      {row.sub ? <span className="sub mono">{row.sub}</span> : null}
                    </div>
                  )
                })}
              </div>
            ))
          ) : (
            <div
              className={'palrow' + (index === 0 ? ' sel' : '')}
              style={{ cursor: 'default', color: 'var(--sub)' }}
            >
              {T('pal_none')}
            </div>
          )}
        </div>
        <div className="palfoot">
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> {T('pal_move')}
          </span>
          <span>
            <kbd>↵</kbd> {T('pal_pick')}
          </span>
          <span>
            <kbd>Esc</kbd> {T('pal_close')}
          </span>
        </div>
      </div>
    </div>
  )
}
