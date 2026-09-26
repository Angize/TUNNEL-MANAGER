import { useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Reveal from '../../components/Reveal.jsx'
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
  color: 'var(--ok-tx)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 7,
}

const EXIT_MS = 260

function alertKey(alert) {
  const who =
    alert.id != null
      ? alert.id
      : alert.node != null
        ? alert.node
        : alert.stray
          ? alert.stray.node + ':' + alert.stray.name
          : alert.kind === 'store'
            ? alert.msg
            : ''
  return alert.kind + ':' + alert.level + ':' + who
}

function merge(prev, alerts) {
  const keys = new Set()
  const next = []
  for (const alert of alerts) {
    const base = alertKey(alert)
    let key = base
    for (let n = 2; keys.has(key); n++) key = base + '~' + n
    keys.add(key)
    next.push({ key, alert, out: false })
  }
  prev.forEach((row, i) => {
    if (keys.has(row.key)) return
    next.splice(Math.min(i, next.length), 0, { ...row, out: true })
  })
  const had = new Set(prev.map((row) => row.key))
  return next.map((row) => (had.has(row.key) ? row : { ...row, fresh: true }))
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
  const [rows, setRows] = useState(() => merge([], alerts).map((row) => ({ ...row, fresh: false })))
  const [from, setFrom] = useState(alerts)
  const [won, setWon] = useState(false)

  if (alerts !== from) {
    setFrom(alerts)
    setRows(merge(rows, alerts))
    if (alerts.length) setWon(false)
  }

  useEffect(() => {
    if (!rows.some((row) => row.out)) return undefined
    const timer = setTimeout(() => {
      const left = rows.filter((row) => !row.out)
      setRows(left)
      if (!left.length) setWon(true)
    }, EXIT_MS)
    return () => clearTimeout(timer)
  }, [rows])

  const dropStray = async (stray) => {
    if (busy || !(await confirmBox(TF('ov_stray_del_q', { name: stray.name }), T('ov_stray_del')))) return
    setBusy(stray.node + ':' + stray.name)
    const r = await apiPost('stray-del', stray)
    setBusy('')
    if (r.ok && r.d.ok) toast(T('ov_stray_del_ok'), 'ok')
    else toast(postError(r), 'err')
  }

  if (!rows.length) {
    return (
      <div className={'card ogood' + (won ? ' won' : '')}>
        <div style={EMPTY_STYLE}>
          <Icon name="okc" color="var(--ok-tx)" />
          {T('ov_noalert')}
        </div>
      </div>
    )
  }

  return (
    <div className="card oalerts">
      {rows.map(({ key, alert, out, fresh }) => {
        const page = alert.tab || 'nodes'
        const jump = () => {
          setPageQuery(page, '')
          onNavigate(page)
        }
        const color = alert.level === 'bad' ? cssVar('--bad') : cssVar('--gold')
        return (
          <Reveal key={key} show={!out} appear={fresh}>
            <div className="oalert">
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
          </Reveal>
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
