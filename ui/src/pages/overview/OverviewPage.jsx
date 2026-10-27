import { useCallback, useRef } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import AlertList from './AlertList.jsx'
import NodeHeat from './NodeHeat.jsx'
import Gauge from './Gauge.jsx'
import TunnelBreakdown from './TunnelBreakdown.jsx'
import TrafficChart from './TrafficChart.jsx'
import { T, TF } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { scoreColor, uptimeColor, usageColor, usageLevel } from '../../lib/health.js'
import { fmtBytes, num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const LIVE_POINTS = 26

function Section({ icon, titleKey, children }) {
  return (
    <section className="osec">
      <h2 className="sec">
        <Icon name={icon} color="var(--acc-tx)" />
        {T(titleKey)}
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
  return (
    <div className="wrow">
      <span className="wk">{label}</span>
      <span className="wnm" dir="auto" title={entry.name}>
        {entry.name}
      </span>
      <span className="wbar">
        <i className={usageLevel(pct, crit)} style={{ width: pct + '%' }} />
      </span>
      <span className="wpc" style={{ color: usageColor(pct, crit) }}>
        {pct + T('pct')}
      </span>
    </div>
  )
}

function gb(mb) {
  const v = num(mb) / 1024
  return v < 10 ? v.toFixed(1) : Math.round(v)
}

export default function OverviewPage({ onNavigate }) {
  const config = useUiConfig()
  const crit = num(config.usage_crit_pct)
  const live = useRef([])

  const load = useCallback(async (onProgress) => {
    const summary = await apiGet('summary', onProgress)
    live.current = [
      ...live.current,
      { t: Date.now(), rx: num(summary.fleet_rx_bps), tx: num(summary.fleet_tx_bps) },
    ].slice(-LIVE_POINTS)
    return summary
  }, [])

  const [summary, , progress] = usePolledData(load)
  const body = useRef(null)
  useRiseIn(body, !!summary)

  if (!summary) {
    return (
      <>
        <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />
        <LoadBar on value={progress} />
      </>
    )
  }

  const alerts = summary.alerts || []
  const alertCount = num(summary.alert_count)
  const score = num(summary.health_score)
  const central = summary.central || {}
  const load1 = (central.load || [])[0]
  const worst = summary.worst || {}
  const linksUp = num(summary.link_up)
  const linksOff = num(summary.link_off)
  const linksOn = num(summary.link_total) - linksOff
  const tunNote = !num(summary.link_total)
    ? T('ov_no_tunnel')
    : linksOff
      ? TF('ov_kpi_tun_off', { n: linksOff })
      : null
  const uptimeWindow = num(summary.uptime_window) || 1

  return (
    <>
      <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />
      <LoadBar on={false} />

      <div ref={body}>
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
            value={linksUp}
            total={linksOn}
            color={linksUp === linksOn ? 'var(--ok-tx)' : linksUp ? 'var(--gold-tx)' : 'var(--bad-tx)'}
            note={tunNote}
          />
          <Kpi
            label={T('ov_kpi_alerts')}
            value={alertCount}
            color={alertCount ? 'var(--bad-tx)' : 'var(--ok-tx)'}
          />
        </div>

        <div className="ogrid oduo">
          <Section icon="warn" titleKey="ov_attention">
            <AlertList alerts={alerts} onNavigate={onNavigate} />
          </Section>

          <Section icon="traf" titleKey="ov_traffic">
            <div className="card otraf">
              <TrafficChart live={live.current} now={{ rx: summary.fleet_rx_bps, tx: summary.fleet_tx_bps }} />
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
          <NodeHeat heat={summary.heat || []} onNavigate={onNavigate} />
        </Section>

        <div className="ogrid">
          <Section icon="server" titleKey="ov_central">
            <div className="card ocentral">
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
                      ? gb(central.mem_used_mb) + ' / ' + gb(central.mem_total_mb) + ' ' + T('unit_gb')
                      : '—'
                  }
                />
                <Gauge
                  label={T('disk')}
                  pct={central.disk_pct}
                  sub={
                    central.disk_used_mb != null
                      ? gb(central.disk_used_mb) + ' / ' + gb(central.disk_total_mb) + ' ' + T('unit_gb')
                      : '—'
                  }
                />
              </div>
            </div>
          </Section>

          <Section icon="activity" titleKey="ov_worst">
            <div className="card">
              {worst.disk || worst.ram || worst.cpu ? (
                <div className="owst">
                  <WorstRow label={T('disk')} entry={worst.disk} crit={crit} />
                  <WorstRow label={T('ram')} entry={worst.ram} crit={crit} />
                  <WorstRow label="CPU" entry={worst.cpu} crit={crit} />
                </div>
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
                <div className="big" style={{ color: uptimeColor(num(summary.uptime_avg), config.uptime_levels) }}>
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
      </div>
    </>
  )
}
