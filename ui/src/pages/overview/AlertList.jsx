import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { T, TF } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { confirmBox } from '../../lib/dialog.js'
import { postError } from '../../lib/errors.js'
import { cssVar } from '../../lib/health.js'
import { setPageQuery } from '../../lib/pageQuery.js'
import { toast } from '../../lib/toast.js'

const PAGE_LABEL = {
  nodes: 'nav_nodes',
  tunnels: 'tun_title',
  core: 'core_title',
  settings: 'nav_settings',
  'set-upkeep': 'set_tab_upkeep',
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

function onKey(fn) {
  return (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      fn()
    }
  }
}

export default function AlertList({ alerts, total, onNavigate }) {
  const [busy, setBusy] = useState('')

  const dropStray = async (stray) => {
    if (busy || !(await confirmBox(TF('ov_stray_del_q', { name: stray.name }), T('ov_stray_del')))) return
    setBusy(stray.node + ':' + stray.name)
    const r = await apiPost('stray-del', stray)
    setBusy('')
    if (r.ok && r.d.ok) toast(T('ov_stray_del_ok'), 'ok')
    else toast(postError(r), 'err')
  }

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
        const page = alert.tab || 'nodes'
        const jump = () => {
          setPageQuery(page, '')
          onNavigate(page)
        }
        const color = alert.level === 'bad' ? cssVar('--bad') : cssVar('--gold')
        return (
          <div className="oalert" key={alert.kind + ':' + alert.msg + ':' + i}>
            <span className="dot" style={{ background: color }} />
            <span className="msg">{alert.msg}</span>
            {alert.stray ? (
              <span
                className="go del"
                role="button"
                tabIndex={0}
                aria-disabled={busy === alert.stray.node + ':' + alert.stray.name}
                onClick={() => dropStray(alert.stray)}
                onKeyDown={onKey(() => dropStray(alert.stray))}
              >
                {T('ov_stray_del')}
              </span>
            ) : null}
            <span className="go" role="button" tabIndex={0} onClick={jump} onKeyDown={onKey(jump)}>
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
