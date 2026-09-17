import { useCallback, useRef } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import { OverviewSkeleton } from '../../components/Skeleton.jsx'
import AlertList from './AlertList.jsx'
import NodeHeat from './NodeHeat.jsx'
import Gauge from './Gauge.jsx'
import TunnelBreakdown from './TunnelBreakdown.jsx'
import Sparkline from './Sparkline.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { scoreColor, usageColor } from '../../lib/health.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'

const SPARK_POINTS = 26

function Chip({ kind, label, value, ltr }) {
  return (
    <span className={'ochip ' + kind}>
      {label} {value != null ? <b dir={ltr ? 'ltr' : undefined}>{value}</b> : null}
    </span>
  )
}

function WorstRow({ label, entry }) {
  if (!entry) return null
  const pct = num(entry.pct)
  const color = usageColor(pct)
  return (
    <div className="wrow">
      <span className="wk">{label}</span>
      <span className="wnm">{entry.name}</span>
      <span className="wbar">
        <i style={{ width: pct + '%', background: color }} />
      </span>
      <span className="wpc" style={{ color }}>
        {pct + T('pct')}
      </span>
    </div>
  )
}

export default function OverviewPage({ onNavigate }) {
  const rxHistory = useRef([])
  const txHistory = useRef([])

  const load = useCallback(async () => {
    const summary = await apiGet('summary')
    rxHistory.current = [...rxHistory.current, num(summary.fleet_rx_bps)].slice(-SPARK_POINTS)
    txHistory.current = [...txHistory.current, num(summary.fleet_tx_bps)].slice(-SPARK_POINTS)
    return summary
  }, [])

  const [summary] = usePolledData(load)

  if (!summary) {
    return (
      <>
        <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />
        <OverviewSkeleton />
      </>
    )
  }

  const alerts = summary.alerts || []
  const score = num(summary.health_score)
  const central = summary.central || {}
  const load1 = (central.load || [])[0]
  const worst = summary.worst || {}
  const linkTotal = num(summary.link_total) - num(summary.link_off)
  const uptimeWindow = num(summary.uptime_window) || 1

  return (
    <>
      <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />

      <div className="card ohero">
        <div>
          <div className="oscore" style={{ color: scoreColor(score) }}>
            {score}
          </div>
          <div className="oscore-l">{T('ov_health')}</div>
        </div>
        <div className="ochips">
          <Chip kind="a" label={T('ov_chip_node')} value={num(summary.nodes_online) + '/' + num(summary.nodes_total)} ltr />
          <Chip kind="o" label={T('ov_chip_uplink')} value={num(summary.link_up) + '/' + linkTotal} ltr />
          <Chip kind="a" label={T('ov_chip_tunnel')} value={num(summary.link_total)} />
          {alerts.length ? (
            <Chip kind="b" label={T('ov_chip_alert')} value={num(summary.alert_count)} />
          ) : (
            <Chip kind="o" label={T('ov_chip_noalert')} />
          )}
        </div>
      </div>

      <div className="sec">
        <Icon name="warn" color="var(--acc)" />
        {T('ov_attention')}
      </div>
      <AlertList alerts={alerts} total={num(summary.alert_count)} onNavigate={onNavigate} />

      <div className="sec">
        <Icon name="grid" color="var(--acc)" />
        {T('ov_allnodes')}
      </div>
      <NodeHeat heat={summary.heat || []} />

      <div className="sec">
        <Icon name="server" color="var(--acc)" />
        {T('ov_central')}
      </div>
      <div className="card">
        <div className="gauges">
          <Gauge
            label="CPU"
            pct={central.cpu_pct}
            sub={
              T('load') +
              ' ' +
              (load1 != null ? load1 : '—') +
              ' · ' +
              (num(central.cpus) || '?') +
              ' ' +
              T('cores_word')
            }
          />
          <Gauge
            label="RAM"
            pct={central.ram_pct}
            sub={
              central.mem_used_mb != null
                ? num(central.mem_used_mb) + ' / ' + num(central.mem_total_mb) + ' ' + T('unit_mb')
                : '—'
            }
          />
          <Gauge
            label={T('disk')}
            pct={central.disk_pct}
            sub={
              central.disk_used_mb != null
                ? Math.round(num(central.disk_used_mb) / 1024) +
                  ' / ' +
                  Math.round(num(central.disk_total_mb) / 1024) +
                  ' ' +
                  T('unit_gb')
                : '—'
            }
          />
        </div>
      </div>

      <div className="sec">
        <Icon name="activity" color="var(--acc)" />
        {T('ov_worst')}
      </div>
      <div className="card">
        {worst.disk || worst.ram || worst.cpu ? (
          <>
            <WorstRow label={T('disk')} entry={worst.disk} />
            <WorstRow label={T('ram')} entry={worst.ram} />
            <WorstRow label="CPU" entry={worst.cpu} />
          </>
        ) : (
          <div
            className="muted"
            style={{ textAlign: 'center', padding: '8px 0', fontSize: 12.5 }}
          >
            {T('ov_no_online')}
          </div>
        )}
      </div>

      <div className="sec">
        <Icon name="link" color="var(--acc)" />
        {T('ov_tunbreak')}
      </div>
      <TunnelBreakdown summary={summary} />

      <div className="sec">
        <Icon name="traf" color="var(--acc)" />
        {T('ov_traffic')}
        <span className="lpill">
          <span className="pd" />
          {T('live')}
        </span>
      </div>
      <div className="card">
        <div className="tf-chart">
          <div className="tf-top">
            <span className="din iso">
              ↓ <b>{fmtRate(summary.fleet_rx_bps)}</b>
            </span>
            <span className="dout iso">
              ↑ <b>{fmtRate(summary.fleet_tx_bps)}</b>
            </span>
          </div>
          <Sparkline rx={rxHistory.current} tx={txHistory.current} />
        </div>
        <div className="ttiles">
          <div className="ttile">
            <span className="din">{T('ov_rxtot')}</span>
            <b>{fmtBytes(summary.fleet_rx_total)}</b>
          </div>
          <div className="ttile">
            <span className="dout">{T('ov_txtot')}</span>
            <b>{fmtBytes(summary.fleet_tx_total)}</b>
          </div>
        </div>
      </div>

      <div className="sec">
        <Icon name="clock" color="var(--acc)" />
        {T('ov_uptime')}
      </div>
      <div className="ostat2">
        <div className="card">
          <div className="big" style={{ color: 'var(--ok)' }}>
            {num(summary.uptime_avg) + T('pct')}
          </div>
          <div className="muted" style={{ fontSize: 11.5 }}>
            {T('ov_uptime_lbl') + ' ' + uptimeWindow + ' ' + T('ov_hours_recent')}
          </div>
        </div>
        <div className="card">
          <div className="big">{num(summary.uptime_down_nodes)}</div>
          <div className="muted" style={{ fontSize: 11.5 }}>
            {T('ov_down_nodes')}
          </div>
        </div>
      </div>
    </>
  )
}
