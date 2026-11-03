import Icon from '../components/Icon.jsx'
import { NAV_ITEMS, unreadText } from './Sidebar.jsx'
import { T } from '../i18n/fa.js'

export default function TabBar({ page, unread, onNavigate }) {
  return (
    <nav className="tabbar">
      {NAV_ITEMS.map((it) => (
        <button
          key={it.id}
          type="button"
          className={'tab' + (page === it.id ? ' on' : '')}
          title={T('nav_' + it.id)}
          aria-label={T('nav_' + it.id)}
          aria-current={page === it.id ? 'page' : undefined}
          onClick={() => onNavigate(it.id)}
        >
          <Icon name={it.icon} />
          <span className="tlbl">{T('nav_' + it.id)}</span>
          {it.id === 'logs' && unread > 0 ? (
            <i className="tbadge">{unreadText(unread)}</i>
          ) : null}
        </button>
      ))}
    </nav>
  )
}
