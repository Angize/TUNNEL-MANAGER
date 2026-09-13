import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { cssVar } from '../../lib/health.js'

const PAGE_FOR_KIND = {
  node: 'nodes',
  link: 'tunnels',
  drift: 'tunnels',
  disk: 'nodes',
  ram: 'nodes',
  cpu: 'nodes',
  agent: 'settings',
}

const PAGE_LABEL = {
  nodes: 'nav_nodes',
  tunnels: 'tun_title',
  settings: 'nav_settings',
}

const EMPTY_STYLE = {
  textAlign: 'center',
  padding: '10px 0',
  fontSize: 12.5,
  color: 'var(--ok)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 7,
}

export default function AlertList({ alerts, onNavigate }) {
  if (!alerts.length) {
    return (
      <div className="card">
        <div style={EMPTY_STYLE}>
          <Icon name="okc" color="var(--ok)" />
          {T('ov_noalert')}
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      {alerts.map((alert, i) => {
        const page = PAGE_FOR_KIND[alert.kind] || 'nodes'
        const color = alert.level === 'bad' ? cssVar('--bad') : cssVar('--gold')
        return (
          <div className="oalert" key={alert.kind + ':' + alert.msg + ':' + i}>
            <span className="dot" style={{ background: color }} />
            <span className="msg">{alert.msg}</span>
            <span
              className="go"
              role="button"
              tabIndex={0}
              onClick={() => onNavigate(page)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onNavigate(page)
                }
              }}
            >
              {T(PAGE_LABEL[page])} →
            </span>
          </div>
        )
      })}
    </div>
  )
}
