import { useRef } from 'react'
import Icon from '../components/Icon.jsx'
import useIndicator from '../lib/useIndicator.js'
import { T } from '../i18n/fa.js'
import { logout } from '../lib/api.js'

const ITEMS = [
  { id: 'overview', icon: 'dash' },
  { id: 'nodes', icon: 'server', count: 'nodes_total' },
  { id: 'proxies', icon: 'globe', count: 'proxies' },
  { id: 'tunnels', icon: 'link', count: 'links' },
  { id: 'portfw', icon: 'fwd', count: 'portfw' },
  { id: 'core', icon: 'cpu', count: 'core' },
  { id: 'logs', icon: 'list', count: 'log_count' },
  { id: 'settings', icon: 'cog' },
]

function Count({ value }) {
  if (value == null || value === '') return null
  return <span className="ct">{value}</span>
}

export default function Sidebar({ page, counts, unread, onNavigate }) {
  const nav = useRef(null)
  const ind = useIndicator(nav, page, 'y')

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
        {ITEMS.map((it) => (
          <a
            key={it.id}
            className={'navi' + (page === it.id ? ' on' : '')}
            onClick={() => onNavigate(it.id)}
          >
            <Icon name={it.icon} />
            <span className="nlbl">{T('nav_' + it.id)}</span>
            {it.id === 'logs' ? (
              <span className="ctwrap">
                <Count value={counts[it.count]} />
                {unread > 0 ? (
                  <span className="ct ctun">{unread > 99 ? '99+' : String(unread)}</span>
                ) : null}
              </span>
            ) : (
              <Count value={it.count ? counts[it.count] : null} />
            )}
          </a>
        ))}
        <a className="navi" onClick={logout}>
          <Icon name="logout" />
          <span className="nlbl">{T('nav_logout')}</span>
        </a>
      </nav>
    </aside>
  )
}
