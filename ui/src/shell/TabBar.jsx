import Icon from '../components/Icon.jsx'
import { T } from '../i18n/fa.js'

const ITEMS = [
  { id: 'overview', icon: 'dash' },
  { id: 'nodes', icon: 'server' },
  { id: 'proxies', icon: 'globe' },
  { id: 'tunnels', icon: 'link' },
  { id: 'portfw', icon: 'fwd' },
  { id: 'core', icon: 'cpu' },
  { id: 'logs', icon: 'list' },
  { id: 'settings', icon: 'cog' },
]

export default function TabBar({ page, unread, onNavigate }) {
  return (
    <nav className="tabbar">
      {ITEMS.map((it) => (
        <button
          key={it.id}
          type="button"
          className={'tab' + (page === it.id ? ' on' : '')}
          title={T('nav_' + it.id)}
          onClick={() => onNavigate(it.id)}
        >
          <Icon name={it.icon} />
          <span>{T('nav_' + it.id)}</span>
          {it.id === 'logs' && unread > 0 ? (
            <i className="tbadge">{unread > 99 ? '99+' : String(unread)}</i>
          ) : null}
        </button>
      ))}
    </nav>
  )
}
