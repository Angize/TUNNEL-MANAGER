import { useCallback, useRef } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import { OverviewSkeleton } from '../../components/Skeleton.jsx'
import AlertList from './AlertList.jsx'
import NodeHeat from './NodeHeat.jsx'
import Gauge from './Gauge.jsx'
import TunnelBreakdown from './TunnelBreakdown.jsx'
import Sparkline from './Sparkline.jsx'
import { T, TF } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { scoreColor, usageColor } from '../../lib/health.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const SPARK_POINTS = 26

function Section({ icon, titleKey, extra, children }) {
  return (
    <section className="osec">
      <h2 className="sec">
        <Icon name={icon} color="var(--acc-tx)" />
        {T(titleKey)}
        {extra}
      </h2>
      {children}
    </section>
  )
}

function Kpi({ label, value, total, color, note }) {
  return (
    <div className="card okpi">
      <div className="okl">{label}</div>
      <div className="okv">
        <span className="iso" style={{ color }}>
          {value}
          {total != null ? <span className="okt">/{total}</span> : null}
        </span>
      </div>
      {note ? <div className="okn">{note}</div> : null}
    </div>
  )
}

function WorstRow({ label, entry, crit }) {
  if (!entry) return null
  const pct = num(entry.pct)
  const color = usageColor(pct, crit)
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
  const crit = num(useUiConfig().usage_crit_pct)
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
  const alertCount = num(summary.alert_count)
  const score = num(summary.health_score)
  const central = summary.central || {}
  const load1 = (central.load || [])[0]
  const worst = summary.worst || {}
  const linksOn = num(summary.link_total) - num(summary.link_off)
  const uptimeWindow = num(summary.uptime_window) || 1

  return (
    <>
      <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />

      <div className="okpis">
        <Kpi label={T('ov_health')} value={score} color={scoreColor(score)} />
        <Kpi
          label={T('ov_kpi_nodes')}
          value={num(summary.nodes_online)}
          total={num(summary.nodes_total)}
          color="var(--acc-tx)"
        />
        <Kpi
          label={T('ov_kpi_tunnels')}
          value={num(summary.link_up)}
          total={linksOn}
          color="var(--ok-tx)"
          note={TF('ov_kpi_tun_total', { n: num(summary.link_total) })}
        />
        <Kpi
          label={T('ov_kpi_alerts')}
          value={alertCount}
          color={alertCount ? 'var(--bad-tx)' : 'var(--ok-tx)'}
          note={alertCount ? null : T('ov_chip_noalert')}
        />
      </div>

      <div className="ogrid oduo">
        <Section icon="warn" titleKey="ov_attention">
          <AlertList alerts={alerts} total={alertCount} onNavigate={onNavigate} />
        </Section>

        <Section
          icon="traf"
          titleKey="ov_traffic"
          extra={
            <span className="lpill">
              <span className="pd" />
              {T('live')}
            </span>
          }
        >
          <div className="card otraf">
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
        </Section>
      </div>

      <Section icon="grid" titleKey="ov_allnodes">
        <NodeHeat heat={summary.heat || []} />
      </Section>

      <div className="ogrid">
        <Section icon="server" titleKey="ov_central">
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
                label={T('ram')}
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
        </Section>

        <Section icon="activity" titleKey="ov_worst">
          <div className="card">
            {worst.disk || worst.ram || worst.cpu ? (
              <>
                <WorstRow label={T('disk')} entry={worst.disk} crit={crit} />
                <WorstRow label={T('ram')} entry={worst.ram} crit={crit} />
                <WorstRow label="CPU" entry={worst.cpu} crit={crit} />
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
        </Section>

        <Section icon="link" titleKey="ov_tunbreak">
          <TunnelBreakdown summary={summary} />
        </Section>

        <Section icon="clock" titleKey="ov_uptime">
          <div className="ostat2">
            <div className="card">
              <div className="big" style={{ color: scoreColor(num(summary.uptime_avg)) }}>
                {num(summary.uptime_avg) + T('pct')}
              </div>
              <div className="muted ostat-l">
                {T('ov_uptime_lbl') + ' ' + uptimeWindow + ' ' + T('ov_hours_recent')}
              </div>
            </div>
            <div className="card">
              <div className="big">{num(summary.uptime_down_nodes)}</div>
              <div className="muted ostat-l">{T('ov_down_nodes')}</div>
            </div>
          </div>
        </Section>
      </div>
    </>
  )
}
