import { useRef } from 'react'
import Icon from '../components/Icon.jsx'
import useIndicator from '../lib/useIndicator.js'
import { T } from '../i18n/fa.js'
import { logout } from '../lib/api.js'
import { pressable } from '../lib/keys.js'
import { FLEET_KINDS } from '../pages/fleet/FleetPage.jsx'
import { LINK_KINDS } from '../pages/links/LinksPage.jsx'

export const NAV_ITEMS = [
  { id: 'overview', icon: 'dash' },
  { id: 'fleet', icon: 'server', count: FLEET_KINDS.map((k) => k.count) },
  { id: 'links', icon: 'link', count: LINK_KINDS.map((k) => k.count) },
  { id: 'logs', icon: 'list', count: 'log_count' },
  { id: 'settings', icon: 'cog' },
]

export function unreadText(n) {
  return n > 99 ? '99+' : String(n)
}

function Count({ value }) {
  if (value == null || value === '') return null
  return <span className="ct">{value}</span>
}

function countOf(counts, key) {
  if (!key) return null
  if (!Array.isArray(key)) return counts[key]
  const parts = key.map((k) => counts[k]).filter((v) => v != null && v !== '')
  return parts.length ? parts.reduce((sum, v) => sum + Number(v), 0) : null
}

export default function Sidebar({ page, counts, unread, dark, onNavigate, onToggleTheme }) {
  const nav = useRef(null)
  const ind = useIndicator(nav, page)

  return (
    <aside className="side">
      <div className="sbrand">
        <span className="logo">
          <Icon name="shield" />
        </span>
        <span>
          TUNNEL-MANAGER
          <small>{T('brand_sub')}</small>
        </span>
      </div>
      <nav className="nav" ref={nav}>
        <span className="navind" style={ind} />
        {NAV_ITEMS.map((it) => (
          <a
            key={it.id}
            className={'navi' + (page === it.id ? ' on' : '')}
            aria-current={page === it.id ? 'page' : undefined}
            {...pressable(() => onNavigate(it.id))}
          >
            <Icon name={it.icon} />
            <span>{T('nav_' + it.id)}</span>
            {it.id === 'logs' ? (
              <span className="ctwrap">
                <Count value={counts[it.count]} />
                {unread > 0 ? <span className="ct ctun">{unreadText(unread)}</span> : null}
              </span>
            ) : (
              <Count value={countOf(counts, it.count)} />
            )}
          </a>
        ))}
        <a className="navi" {...pressable(onToggleTheme)}>
          <Icon name={dark ? 'sun' : 'moon'} />
          <span>{T(dark ? 'theme_to_light' : 'theme_to_dark')}</span>
        </a>
        <a className="navi" {...pressable(logout)}>
          <Icon name="logout" />
          <span>{T('nav_logout')}</span>
        </a>
      </nav>
    </aside>
  )
}
