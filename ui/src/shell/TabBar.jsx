import { useRef } from 'react'
import Icon from '../components/Icon.jsx'
import useIndicator from '../lib/useIndicator.js'
import { T } from '../i18n/fa.js'

const ITEMS = [
  { id: 'overview', icon: 'dash' },
  { id: 'nodes', icon: 'server' },
  { id: 'core', icon: 'cpu' },
  { id: 'logs', icon: 'list' },
]

export default function TabBar({ page, unread, onNavigate, onMore }) {
  const bar = useRef(null)
  const ind = useIndicator(bar, page, 'x')
  const listed = ITEMS.some((it) => it.id === page)

  return (
    <nav className="tabbar" ref={bar}>
      <span className="tabind" style={ind} />
      {ITEMS.map((it) => (
        <button
          key={it.id}
          type="button"
          className={'tab' + (page === it.id ? ' on' : '')}
          onClick={() => onNavigate(it.id)}
        >
          <Icon name={it.icon} />
          <span>{T('nav_' + it.id)}</span>
          {it.id === 'logs' && unread > 0 ? (
            <i className="tbadge">{unread > 99 ? '99+' : String(unread)}</i>
          ) : null}
        </button>
      ))}
      <button type="button" className={'tab' + (listed ? '' : ' on')} onClick={onMore}>
        <Icon name="menu" />
        <span>{T('nav_more')}</span>
      </button>
    </nav>
  )
}
