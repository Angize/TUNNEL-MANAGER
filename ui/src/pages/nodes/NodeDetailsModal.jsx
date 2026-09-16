import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import IpChips from '../../components/IpChips.jsx'
import Gauge from '../overview/Gauge.jsx'
import Sparkline from '../overview/Sparkline.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { readError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, fmtUptime, num } from '../../lib/num.js'

const POLL_MS = 2000
const SPARK_POINTS = 30

function Tile({ icon, label, children, wide, ltr }) {
  return (
    <div className={'nd-tile' + (wide ? ' nd-wide' : '')}>
      <span className="medi">
        <Icon name={icon} />
      </span>
      <span>{label}</span>
      <b className={ltr ? 'ltr' : undefined}>{children}</b>
    </div>
  )
}

function CentralCell({ node }) {
  const got = (node.info && node.info.central) || ''
  if (!got) return <span className="muted">{T('nd_central_none')}</span>
  const want = node.central_want || ''
  const stale = !!(got && want && got !== want)
  return <span className={'mono' + (stale ? ' cn-stale' : '')}>{got}</span>
}

function TrafficRow({ row }) {
  return (
    <div className="tf-row">
      <div className="tf-nm">
        <span className="mono">{row.name}</span>
      </div>
      <div className="tf-fig">
        <span className="din iso">↓{fmtRate(row.rx_bps)}</span>
        <span className="dout iso">↑{fmtRate(row.tx_bps)}</span>
        <span className="tot iso">
          <b className="din">↓{fmtBytes(row.rx_total)}</b>{' '}
          <b className="dout">↑{fmtBytes(row.tx_total)}</b>
        </span>
      </div>
    </div>
  )
}

export default function NodeDetailsModal({ node, onClose }) {
  const [online, setOnline] = useState(!!node.online)
  const [stats, setStats] = useState((node.info && node.info.stats) || {})
  const [traffic, setTraffic] = useState(null)
  const [rows, setRows] = useState([])
  const [ips, setIps] = useState(null)
  const rxHistory = useRef([])
  const txHistory = useRef([])

  useEffect(() => {
    if (!node.online) return undefined
    let alive = true

    apiPost('node-ips', { id: node.id })
      .then((v) => {
        if (alive) setIps((v.d && v.d.ips) || [])
      })
      .catch(() => {})

    const poll = () => {
      apiGet('node-stats?id=' + node.id)
        .then((r) => {
          if (!alive) return
          if (r.online) {
            setStats(r.stats)
            setOnline(true)
          } else {
            setOnline(false)
          }
        })
        .catch(() => {})

      apiGet('traffic?id=' + node.id)
        .then((r) => {
          if (!alive) return
          setTraffic(r.node)
          rxHistory.current = [...rxHistory.current, num(r.node.rx_bps)].slice(-SPARK_POINTS)
          txHistory.current = [...txHistory.current, num(r.node.tx_bps)].slice(-SPARK_POINTS)
          setRows(r.tunnels.concat(r.portfw))
        })
        .catch(() => {})
    }

    poll()
    const timer = setInterval(poll, POLL_MS)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [node.id, node.online])

  const retest = () => {
    apiGet('node-stats?id=' + node.id)
      .then((r) => {
        if (r.online) toast(T('online'), 'ok')
        else toast(T('offline') + ': ' + (r.error || T('not_available')), 'err')
      })
      .catch((e) => toast(readError(e), 'err'))
  }

  const info = node.info || {}
  const ramPct = stats.mem_total_mb
    ? Math.round((num(stats.mem_used_mb) / num(stats.mem_total_mb)) * 100)
    : 0

  const subtitle = node.online ? (
    <>
      <span className="lpill">
        <span className="pd" />
        {T('live')}
      </span>{' '}
      {online ? T('refresh2s') : T('nd_off_last')}
    </>
  ) : (
    T('nd_status')
  )

  const footer = (
    <>
      <button className="primary" onClick={retest}>
        {T('nd_conn_test')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('close')}
      </button>
    </>
  )

  return (
    <Modal
      icon="info"
      title={T('nd_title')}
      subtitle={subtitle}
      footer={footer}
      cls="ndsheet"
      onClose={onClose}
    >
      <div className="nd-head">
        <span className={'dot ' + (online ? 'ok' : 'bad')} />
        <div className="nd-id">
          <b className="nd-name">{node.name}</b>
          <span className="nd-hp">
            {node.host}:{node.port}
          </span>
        </div>
        {node.proxy_on ? (
          <span className="tag" style={{ marginInlineStart: 6 }}>
            {T('proxy')}
          </span>
        ) : null}
        <span className={'badge ' + (online ? 'ok' : 'bad') + ' nd-ping'}>
          {online ? T('online') : T('offline')}
        </span>
      </div>

      {node.online ? (
        <>
          <div className="gauges">
            <Gauge
              label="CPU"
              pct={stats.cpu_pct}
              sub={T('load') + ' ' + ((stats.load || [])[0] || '—')}
            />
            <Gauge
              label="RAM"
              pct={ramPct}
              sub={num(stats.mem_used_mb) + ' / ' + num(stats.mem_total_mb) + ' ' + T('unit_mb')}
            />
            <Gauge
              label={T('disk')}
              pct={stats.disk_pct}
              sub={
                stats.disk_used_mb != null
                  ? Math.round(num(stats.disk_used_mb) / 1024) +
                    ' / ' +
                    Math.round(num(stats.disk_total_mb) / 1024) +
                    ' ' +
                    T('unit_gb')
                  : '—'
              }
            />
          </div>

          <div className="nd-sec">
            <Icon name="traf" />
            {T('nd_traffic')}
            <span className="lpill" style={{ marginInlineStart: 'auto' }}>
              <span className="pd" />
              {T('live')}
            </span>
          </div>
          <div className="tf-chart">
            <div className="tf-top">
              <span className="din iso">
                ↓ <b>{traffic ? fmtRate(traffic.rx_bps) : '—'}</b>
              </span>
              <span className="dout iso">
                ↑ <b>{traffic ? fmtRate(traffic.tx_bps) : '—'}</b>
              </span>
            </div>
            <Sparkline rx={rxHistory.current} tx={txHistory.current} />
          </div>
          <div className="ttiles">
            <div className="ttile">
              <span className="din">{T('ov_rxtot')}</span>
              <b>{traffic ? fmtBytes(traffic.rx_total) : '—'}</b>
            </div>
            <div className="ttile">
              <span className="dout">{T('ov_txtot')}</span>
              <b>{traffic ? fmtBytes(traffic.tx_total) : '—'}</b>
            </div>
          </div>
          <div className="tf-tuns">
            {rows.length ? (
              rows.map((row, i) => <TrafficRow row={row} key={row.name + i} />)
            ) : (
              <div className="muted" style={{ fontSize: 11.5, padding: '7px 2px' }}>
                {T('nd_no_tp')}
              </div>
            )}
          </div>

          <div className="nd-divider" />

          <div className="nd-grid">
            <Tile icon="os" label={T('os')} ltr>
              {stats.os || '?'}
            </Tile>
            <Tile icon="clock" label={T('uptime')}>
              {stats.uptime ? fmtUptime(stats.uptime) : '?'}
            </Tile>
            <Tile icon="cores" label={T('cpu_cores')}>
              {num(stats.cpus) || '?'}
            </Tile>
            <Tile icon="link" label={T('nd_tunnels')}>
              {num(info.tunnels)}
            </Tile>
            <Tile icon="globe" label={T('nd_portfw')}>
              {num(info.portfw)}
            </Tile>
            <Tile icon="shield" label={T('nd_ctrlproxy')}>
              {node.proxy_on ? node.proxy_name || '?' : '—'}
            </Tile>
            <Tile icon="server" label={T('host')} wide ltr>
              {info.hostname || '?'}
            </Tile>
            <Tile icon="pin" label={T('ip')} wide ltr>
              {node.host}
            </Tile>
            <Tile icon="globe" label={T('nd_central')} wide ltr>
              <CentralCell node={node} />
            </Tile>
          </div>

          <div className="nd-divider" />

          <div className="nd-sec">
            <Icon name="pin" />
            {T('nd_ips')}
            <span
              className="muted"
              style={{ marginInlineStart: 'auto', fontSize: 11, fontWeight: 500 }}
            >
              {T('ip_leg')}
            </span>
          </div>
          <div className="ndips">
            {ips === null ? (
              <div className="muted" style={{ fontSize: 11.5, padding: '6px 2px' }}>
                …
              </div>
            ) : ips.length ? (
              ips.map((entry) => (
                <div className="iptag" key={entry.ip}>
                  <span className="mono" style={{ direction: 'ltr', fontSize: 12.5 }}>
                    {entry.ip}
                  </span>
                  <span className="tgs">
                    <IpChips entry={entry} />
                  </span>
                </div>
              ))
            ) : (
              <div className="muted" style={{ fontSize: 11.5, padding: '6px 2px' }}>
                {T('ip_none')}
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="nd-off">
          <Icon name="plugoff" />
          <b>{T('not_available')}</b>
          {info.error ? <span>{info.error}</span> : null}
        </div>
      )}
    </Modal>
  )
}
