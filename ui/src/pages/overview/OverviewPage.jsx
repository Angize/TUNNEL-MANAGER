import { useCallback, useRef } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import { SkelKpis, SkelOverview, SkelZone } from '../../components/Skeleton.jsx'
import LoadFail from '../../components/LoadFail.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import AlertList from './AlertList.jsx'
import NodeGroups from './NodeGroups.jsx'
import Gauge from './Gauge.jsx'
import TunnelBreakdown from './TunnelBreakdown.jsx'
import TrafficChart, { pushLive } from './TrafficChart.jsx'
import { T, TF } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { scoreLevel, shareLevel, uptimeColor } from '../../lib/health.js'
import { fmtBytes, fmtGb, num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

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

const LEVEL_WORD = { ok: 'st_healthy', warn: 'st_warn', crit: 'st_crit' }

function Kpi({ label, icon, level, value, total, fill, rest, note }) {
  return (
    <div className={'card okpi l-' + level}>
      <div className="okh">
        <span className="okl">{label}</span>
        <span className="okic" aria-hidden="true">
          <Icon name={icon} />
        </span>
      </div>
      <div className="okv">
        <span className="iso">
          {value}
          {total != null ? <span className="okt">/{total}</span> : null}
        </span>
      </div>
      <div className={rest ? 'okbar rest' : 'okbar'} aria-hidden="true">
        <i style={{ transform: 'scaleX(' + fill + ')' }} />
      </div>
      <div className="okn">{note}</div>
    </div>
  )
}

function share(part, whole) {
  return whole ? part / whole : 0
}

function parts(list) {
  return list.filter(Boolean).join(' · ')
}

export default function OverviewPage({ onNavigate }) {
  const config = useUiConfig()
  const live = useRef([])

  const load = useCallback(async (onProgress) => {
    const summary = await apiGet('summary', onProgress)
    live.current = pushLive(live.current, num(summary.fleet_rx_bps), num(summary.fleet_tx_bps))
    return summary
  }, [])

  const [summary, reload, progress, loadErr] = usePolledData(load)
  const body = useRef(null)
  useRiseIn(body, !!summary)

  if (!summary) {
    return (
      <>
        <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />
        {loadErr ? null : <LoadBar on value={progress} />}
        {loadErr ? (
          <LoadFail text={T('ov_load_fail') + ' ' + loadErr} onRetry={reload} />
        ) : (
          <SkelZone>
            <SkelKpis />
            <SkelOverview />
          </SkelZone>
        )}
      </>
    )
  }

  const alerts = summary.alerts || []
  const alertCount = num(summary.alert_count)
  const alertBad = alerts.filter((a) => a.level === 'bad').length
  const alertWarn = alertCount - alertBad
  const alertLevel = alertBad ? 'crit' : alertWarn ? 'warn' : 'ok'
  const score = num(summary.health_score)
  const central = summary.central || {}
  const load1 = (central.load || [])[0]
  const nodesOn = num(summary.nodes_online)
  const nodesAll = num(summary.nodes_total)
  const linksUp = num(summary.link_up)
  const linksOff = num(summary.link_off)
  const linksOn = num(summary.link_total) - linksOff
  const scoreLvl = scoreLevel(score)
  const nodeNote = !nodesAll
    ? T('ov_no_nodes')
    : nodesAll - nodesOn
      ? TF('ov_kpi_nodes_off', { n: nodesAll - nodesOn })
      : T('ov_kpi_nodes_all')
  const tunNote = !num(summary.link_total)
    ? T('ov_no_tunnel')
    : parts([
        linksOn - linksUp && TF('ov_kpi_tun_bad', { n: linksOn - linksUp }),
        linksOff && TF('ov_kpi_tun_off', { n: linksOff }),
      ]) || T('ov_kpi_tun_all')
  const alertNote =
    parts([
      alertBad && TF('ov_kpi_al_bad', { n: alertBad }),
      alertWarn && TF('ov_kpi_al_warn', { n: alertWarn }),
    ]) || T('ov_kpi_al_none')
  const uptimeWindow = summary.uptime_window

  return (
    <>
      <PageHead icon="dash" titleKey="nav_overview" subKey="ov_sub" />
      <LoadBar on={false} />

      <div ref={body}>
        <div className="okpis">
          <Kpi
            label={T('ov_health')}
            icon="shield"
            level={scoreLvl}
            value={score}
            total={100}
            fill={score / 100}
            note={T(LEVEL_WORD[scoreLvl])}
          />
          <Kpi
            label={T('ov_kpi_nodes')}
            icon="server"
            level={shareLevel(nodesOn, nodesAll)}
            value={nodesOn}
            total={nodesAll}
            fill={share(nodesOn, nodesAll)}
            note={nodeNote}
          />
          <Kpi
            label={T('ov_kpi_tunnels')}
            icon="link"
            level={shareLevel(linksUp, linksOn)}
            value={linksUp}
            total={linksOn}
            fill={share(linksUp, linksOn)}
            note={tunNote}
          />
          <Kpi
            label={T('ov_kpi_alerts')}
            icon={alertCount ? 'warn' : 'okc'}
            level={alertLevel}
            value={alertCount}
            fill={share(alertBad, alertCount)}
            rest={alertWarn > 0}
            note={alertNote}
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
          <NodeGroups heat={summary.heat || []} onNavigate={onNavigate} />
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
                      ? fmtGb(central.mem_used_mb) + ' / ' + fmtGb(central.mem_total_mb) + ' ' + T('unit_gb')
                      : '—'
                  }
                />
                <Gauge
                  label={T('disk')}
                  pct={central.disk_pct}
                  sub={
                    central.disk_used_mb != null
                      ? fmtGb(central.disk_used_mb) + ' / ' + fmtGb(central.disk_total_mb) + ' ' + T('unit_gb')
                      : '—'
                  }
                />
              </div>
            </div>
          </Section>

          <Section icon="link" titleKey="ov_tunbreak">
            <TunnelBreakdown summary={summary} onNavigate={onNavigate} />
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
