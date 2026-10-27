import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import IpChips from '../../components/IpChips.jsx'
import SaveLabel from '../../components/SaveLabel.jsx'
import Gauge from '../overview/Gauge.jsx'
import TrafficChart from '../overview/TrafficChart.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { readError, translateError } from '../../lib/errors.js'
import { getUiInterval } from '../../lib/poll.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, fmtUptime, num } from '../../lib/num.js'
import useBusy from '../../lib/useBusy.js'

const SPARK_POINTS = 30

function gb(mb) {
  const v = num(mb) / 1024
  return v < 10 ? v.toFixed(1) : Math.round(v)
}

function Tile({ icon, label, children, wide, ltr }) {
  return (
    <div className={'nd-tile' + (wide ? ' nd-wide nd-line' : '')}>
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
        <span className="mono" title={row.name}>
          {row.name}
        </span>
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
  const [ipsError, setIpsError] = useState('')
  const live = useRef([])
  const [testing, guard] = useBusy()

  useEffect(() => {
    if (!node.online) return undefined
    let alive = true

    apiPost('node-ips', { id: node.id }).then((v) => {
      if (!alive) return
      if (v.ok) setIps(v.d.ips)
      else setIpsError(readError(v))
    })

    let timer = 0
    const poll = async () => {
      if (!document.hidden) {
        await Promise.all([
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
            .catch(() => {}),
          apiGet('traffic?id=' + node.id)
            .then((r) => {
              if (!alive) return
              setTraffic(r.node)
              live.current = [
                ...live.current,
                { t: Date.now(), rx: num(r.node.rx_bps), tx: num(r.node.tx_bps) },
              ].slice(-SPARK_POINTS)
              setRows(r.tunnels.concat(r.portfw))
            })
            .catch(() => {}),
        ])
      }
      if (alive) timer = setTimeout(poll, getUiInterval())
    }

    poll()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [node.id, node.online])

  const retest = async () => {
    const r = await apiPost('node-test', { id: node.id })
    if (!r.ok) {
      toast(readError(r), 'err')
      return
    }
    const probe = r.d.info || {}
    setOnline(!!r.d.ok)
    if (r.d.ok) {
      setStats(probe.stats || {})
      toast(T('online'), 'ok')
    } else {
      toast(T('offline') + ': ' + (translateError(probe.error) || T('not_available')), 'err')
    }
  }

  const shownOnline = node.online && online

  const info = node.info || {}
  const ramPct = stats.mem_total_mb
    ? Math.round((num(stats.mem_used_mb) / num(stats.mem_total_mb)) * 100)
    : 0

  const subtitle = !node.online ? (
    T('nd_status')
  ) : shownOnline ? (
    <span className="lpill">
      <span className="pd" />
      {T('refresh2s')}
    </span>
  ) : (
    T('nd_off_last')
  )

  const footer = (
    <>
      <button className="primary" disabled={testing} onClick={guard(retest)}>
        <SaveLabel busy={testing}>{T('nd_conn_test')}</SaveLabel>
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
      onClose={onClose}
    >
      <div className="nd-head">
        <span className={'dot ' + (shownOnline ? 'ok' : 'bad')} />
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
        <span className={'badge ' + (shownOnline ? 'ok' : 'bad') + ' nd-ping'}>
          {shownOnline ? T('online') : T('offline')}
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
              label={T('ram')}
              pct={ramPct}
              sub={
                stats.mem_used_mb != null
                  ? gb(stats.mem_used_mb) + ' / ' + gb(stats.mem_total_mb) + ' ' + T('unit_gb')
                  : '—'
              }
            />
            <Gauge
              label={T('disk')}
              pct={stats.disk_pct}
              sub={
                stats.disk_used_mb != null
                  ? gb(stats.disk_used_mb) + ' / ' + gb(stats.disk_total_mb) + ' ' + T('unit_gb')
                  : '—'
              }
            />
          </div>

          <div className="nd-sec">
            <Icon name="traf" />
            {T('nd_traffic')}
          </div>
          <TrafficChart
            nodeId={node.id}
            live={live.current}
            now={traffic ? { rx: traffic.rx_bps, tx: traffic.tx_bps } : null}
          />
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
            <Tile icon="globe" label={T('nd_central')} wide ltr>
              <CentralCell node={node} />
            </Tile>
          </div>

          <div className="nd-divider" />

          <div className="nd-sec">
            <Icon name="pin" />
            {T('nd_ips')}
            <span className="iplg">
              <span>
                <i className="tun" />
                {T('ip_leg_tun')}
              </span>
              <span>
                <i className="pf" />
                {T('nd_portfw')}
              </span>
              <span>
                <i />
                {T('free')}
              </span>
            </span>
          </div>
          <div className="ndips">
            {ips === null ? (
              <div className="muted" style={{ fontSize: 11.5, padding: '6px 2px' }}>
                {ipsError || (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                    <span className="bspin ink sm" />
                    {T('loading')}
                  </span>
                )}
              </div>
            ) : ips.length ? (
              ips.map((entry) => (
                <div className="iptag" key={entry.ip}>
                  <span className="mono ipv" dir="ltr">
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
        <>
          <div className="nd-off">
            <Icon name="plugoff" />
            <b>{T('not_available')}</b>
            {info.error ? <span>{translateError(info.error)}</span> : null}
          </div>
          <div className="nd-sec">
            <Icon name="traf" />
            {T('nd_traffic')}
          </div>
          <TrafficChart nodeId={node.id} live={[]} now={null} initial="1h" />
        </>
      )}
    </Modal>
  )
}
