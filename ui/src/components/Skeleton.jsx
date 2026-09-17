import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'

const LTR_HEAD = { direction: 'ltr', alignItems: 'flex-start', gap: 2, flex: '0 0 auto', minWidth: 0 }
const HEAT_HEIGHTS = [42, 66, 30, 55, 48, 62, 36, 58]
const SETTINGS_GROUPS = [
  ['sc-panel', 6],
  ['sc-conn', 2],
  ['sc-pool', 2],
  ['sc-perf', 1],
  ['sc-panel', 2],
]

export function Sk({ as, className, w, style }) {
  const Tag = as || 'span'
  return (
    <Tag className={(className ? className + ' ' : '') + 'sk'} style={{ width: w, ...style }}>
      &nbsp;
    </Tag>
  )
}

export function Box({ w, h, r, style }) {
  return (
    <span
      className="sk"
      style={{ width: w, height: h, borderRadius: r, flex: '0 0 auto', ...style }}
    />
  )
}

function Dot({ size }) {
  return <Box w={size} h={size} r={size} />
}

function Chevron() {
  return <Box w={16} h={16} r={4} />
}

function Toggle() {
  return <Box w={38} h={22} r={20} />
}

function TrafficRow({ cls }) {
  return (
    <div className={'ltraf' + (cls ? ' ' + cls : '')}>
      <Sk className="din iso" w={72} />
      <Sk className="dout iso" w={72} />
      <span className="tot">
        <Sk w={118} />
      </span>
    </div>
  )
}

export function AccCardSkeleton() {
  return (
    <div className="card acc">
      <div className="chead">
        <Toggle />
        <div className="hmain">
          <div className="hrow1">
            <Sk className="hname" w={40} />
            <Sk className="ctag" w={42} style={{ borderRadius: 20 }} />
            <span className="hpeers" dir="ltr">
              <Dot size={7} />
              <Sk w={28} />
              <Sk w={12} />
              <Sk w={28} />
              <Dot size={7} />
            </span>
          </div>
        </div>
        <Chevron />
      </div>
    </div>
  )
}

export function NodeCardSkeleton() {
  return (
    <div className="card node acc">
      <div className="chead">
        <Toggle />
        <span className="grow" />
        <div className="hmain" style={LTR_HEAD}>
          <Sk as="div" className="name" w={110} />
          <Sk as="div" className="muted mono" w={132} style={{ fontSize: 12 }} />
        </div>
        <Dot size={10} />
        <Chevron />
      </div>
      <TrafficRow cls="ndtraf" />
    </div>
  )
}

export function ProxyCardSkeleton() {
  return (
    <div className="card node acc">
      <div className="chead">
        <span className="grow" />
        <div className="hmain" style={LTR_HEAD}>
          <Sk as="div" className="name" w={96} />
          <Sk as="div" className="muted mono" w={150} style={{ fontSize: 12 }} />
        </div>
        <Dot size={10} />
        <Chevron />
      </div>
    </div>
  )
}

export function PortfwCardSkeleton() {
  return (
    <div className="card acc">
      <div className="chead">
        <div className="hmain">
          <div className="hrow1">
            <Sk className="hname" w={90} />
            <Sk className="ctag" w={50} style={{ borderRadius: 20 }} />
            <Sk as="b" className="mono" w={74} style={{ fontSize: 12 }} />
            <span className="hpeers">
              <Sk className="badge" w={60} style={{ borderRadius: 10 }} />
            </span>
          </div>
        </div>
        <Chevron />
      </div>
    </div>
  )
}

const CARD_SHAPES = {
  tunnel: AccCardSkeleton,
  node: NodeCardSkeleton,
  proxy: ProxyCardSkeleton,
  portfw: PortfwCardSkeleton,
}

export function CardSkeletons({ kind, count }) {
  const Shape = CARD_SHAPES[kind] || AccCardSkeleton
  const n = count > 0 ? Math.min(40, count) : 4
  return Array.from({ length: n }, (_, i) => <Shape key={i} />)
}

export function AgentRowsSkeleton({ count }) {
  const n = count > 0 ? Math.min(40, count) : 4
  return Array.from({ length: n }, (_, i) => (
    <div className="nx" key={i}>
      <div className="nxh">
        <Dot size={10} />
        <span className="nmwrap">
          <Sk className="nm" w={100} />
          <Sk className="nxhost" w={120} />
        </span>
      </div>
      <div className="nxv">
        <Box w={62} h={25} r={8} />
        <Box w={62} h={25} r={8} />
      </div>
      <div className="nxa">
        <Box w={34} h={34} r={10} />
        <Box w={34} h={34} r={10} />
      </div>
    </div>
  ))
}

function Section({ icon, titleKey }) {
  return (
    <div className="sec">
      <Icon name={icon} color="var(--acc)" />
      {T(titleKey)}
    </div>
  )
}

export function OverviewSkeleton() {
  return (
    <>
      <div className="card ohero">
        <div>
          <Sk as="div" className="oscore" w={64} style={{ borderRadius: 8 }} />
          <Sk as="div" className="oscore-l" w={70} />
        </div>
        <div className="ochips">
          <Sk className="ochip" w={82} style={{ borderRadius: 20 }} />
          <Sk className="ochip" w={96} style={{ borderRadius: 20 }} />
          <Sk className="ochip" w={72} style={{ borderRadius: 20 }} />
          <Sk className="ochip" w={88} style={{ borderRadius: 20 }} />
        </div>
      </div>

      <Section icon="warn" titleKey="ov_attention" />
      <div className="card">
        {[0, 1].map((i) => (
          <div className="oalert" key={i}>
            <Dot size={8} />
            <Sk className="msg" w={i ? '46%' : '62%'} />
            <Sk className="go" w={52} />
          </div>
        ))}
      </div>

      <Section icon="grid" titleKey="ov_allnodes" />
      <div className="card ohcard">
        <div className="oheat">
          {HEAT_HEIGHTS.map((h, i) => (
            <span
              className="sk"
              key={i}
              style={{ flex: '1 1 0', maxWidth: 56, height: h, borderRadius: '5px 5px 3px 3px' }}
            />
          ))}
        </div>
        <div className="heat-lg">
          <Sk w={54} />
          <Sk w={54} />
          <Sk w={54} />
        </div>
      </div>

      <Section icon="server" titleKey="ov_central" />
      <div className="card">
        <div className="gauges">
          {[0, 1, 2].map((i) => (
            <div className="gauge" key={i}>
              <div className="gwrap">
                <Box w={84} h={84} r={42} />
              </div>
              <Sk as="div" className="gl" w={34} style={{ margin: '8px auto 0' }} />
              <Sk as="div" className="gsub" w={70} style={{ margin: '2px auto 0' }} />
            </div>
          ))}
        </div>
      </div>

      <Section icon="activity" titleKey="ov_worst" />
      <div className="card">
        {[0, 1, 2].map((i) => (
          <div className="wrow" key={i}>
            <Sk className="wk" w={34} />
            <Sk className="wnm" w={80} />
            <Box w="auto" h={8} r={4} style={{ flex: '1 1 auto' }} />
            <Sk className="wpc" w={32} />
          </div>
        ))}
      </div>

      <Section icon="link" titleKey="ov_tunbreak" />
      <div className="card">
        <div className="tst">
          {[0, 1, 2, 3].map((i) => (
            <div className="tb" key={i}>
              <Sk as="div" className="n" w={36} style={{ margin: '0 auto' }} />
              <Sk as="div" className="l" w={50} style={{ margin: '0 auto' }} />
            </div>
          ))}
        </div>
        <Box w="100%" h={12} r={20} style={{ marginTop: 11 }} />
      </div>

      <Section icon="traf" titleKey="ov_traffic" />
      <div className="card">
        <div className="tf-chart">
          <div className="tf-top">
            <Sk className="din iso" w={90} />
            <Sk className="dout iso" w={90} />
          </div>
          <Box w="100%" h={46} r={8} />
        </div>
        <div className="ttiles">
          {[0, 1].map((i) => (
            <div className="ttile" key={i}>
              <Sk className="din" w={60} />
              <Sk as="b" w={84} />
            </div>
          ))}
        </div>
      </div>

      <Section icon="clock" titleKey="ov_uptime" />
      <div className="ostat2">
        {[0, 1].map((i) => (
          <div className="card" key={i}>
            <Sk as="div" className="big" w={70} style={{ borderRadius: 6 }} />
            <Sk as="div" className="muted" w={120} style={{ fontSize: 11.5 }} />
          </div>
        ))}
      </div>
    </>
  )
}

export function SettingsSkeleton() {
  return (
    <div className="stgrid">
      {SETTINGS_GROUPS.map(([tone, rows]) => (
        <div className={'card sg ' + tone} key={tone}>
          <div className="sghd">
            <Box w={30} h={30} r={9} />
            <Sk as="b" w={110} />
            <Sk className="schip" w={60} style={{ borderRadius: 20 }} />
          </div>
          <div className="sgb">
            {Array.from({ length: rows }, (_, i) => (
              <div className="sr" key={i}>
                <div className="srtop">
                  <b className="srlbl">
                    <Sk w={130} />
                  </b>
                  <Box w={22} h={22} r={11} />
                  <div className="srctl">
                    <Box w="100%" h="var(--sc-h)" r={10} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
