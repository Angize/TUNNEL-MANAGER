import Icon from '../../components/Icon.jsx'
import { T, TF } from '../../i18n/fa.js'
import { cssVar } from '../../lib/health.js'
import { setPageQuery } from '../../lib/pageQuery.js'

const PAGE_FOR_KIND = {
  node: 'nodes',
  disk: 'nodes',
  ram: 'nodes',
  cpu: 'nodes',
  agent: 'settings',
}

const PAGE_LABEL = {
  nodes: 'nav_nodes',
  tunnels: 'tun_title',
  core: 'core_title',
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

export default function AlertList({ alerts, total, onNavigate }) {
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
        const page = alert.tab || PAGE_FOR_KIND[alert.kind] || 'nodes'
        const jump = () => {
          setPageQuery(page, '')
          onNavigate(page)
        }
        const color = alert.level === 'bad' ? cssVar('--bad') : cssVar('--gold')
        return (
          <div className="oalert" key={alert.kind + ':' + alert.msg + ':' + i}>
            <span className="dot" style={{ background: color }} />
            <span className="msg">{alert.msg}</span>
            <span
              className="go"
              role="button"
              tabIndex={0}
              onClick={jump}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  jump()
                }
              }}
            >
              {T(PAGE_LABEL[page])} →
            </span>
          </div>
        )
      })}
      {total > alerts.length ? (
        <div className="oalert">
          <span className="msg muted">{TF('ov_more_alerts', { n: total - alerts.length })}</span>
        </div>
      ) : null}
    </div>
  )
}
