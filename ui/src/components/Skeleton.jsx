import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'

const LTR_HEAD = { direction: 'ltr', alignItems: 'flex-start', gap: 2, flex: '0 0 auto', minWidth: 0 }
const SETTINGS_GROUPS = [
  ['sc-panel', 6],
  ['sc-conn', 2],
  ['sc-pool', 2],
  ['sc-perf', 1],
]

export function Sk({ as, className, w, style }) {
  const Tag = as || 'span'
  return (
    <Tag className={(className ? className + ' ' : '') + 'sk'} style={{ width: w, ...style }}>
      &nbsp;
    </Tag>
  )
}

function Box({ w, h, r, style }) {
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

function AccCardSkeleton() {
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

function NodeCardSkeleton() {
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

function ProxyCardSkeleton() {
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

function PortfwCardSkeleton() {
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
        <Box h={26} r={8} style={{ flex: 1 }} />
        <Box h={26} r={8} style={{ flex: 1 }} />
      </div>
      <div className="nxa">
        <Box h={36} r={10} style={{ flex: 1 }} />
        <Box h={36} r={10} style={{ flex: 1 }} />
      </div>
    </div>
  ))
}

function Section({ icon, titleKey, children }) {
  return (
    <div className="sec">
      <Icon name={icon} color="var(--acc-tx)" />
      {T(titleKey)}
      {children}
    </div>
  )
}

function OvSection({ icon, titleKey, extra, children }) {
  return (
    <section className="osec">
      <Section icon={icon} titleKey={titleKey}>
        {extra}
      </Section>
      {children}
    </section>
  )
}

export function OverviewSkeleton() {
  return (
    <>
      <div className="okpis">
        {[0, 1, 2, 3].map((i) => (
          <div className="card okpi" key={i}>
            <Sk as="div" className="okl" w={72} />
            <Sk as="div" className="okv" w={56} style={{ borderRadius: 8 }} />
          </div>
        ))}
      </div>

      <div className="ogrid oduo">
        <OvSection icon="warn" titleKey="ov_attention">
          <div className="card">
            {[0, 1].map((i) => (
              <div className="oalert" key={i}>
                <Dot size={8} />
                <Sk className="msg" w={i ? '46%' : '62%'} />
                <Sk className="go" w={52} />
              </div>
            ))}
          </div>
        </OvSection>

        <OvSection icon="traf" titleKey="ov_traffic" extra={<Box w={50} h={23} r={20} />}>
          <div className="card otraf">
            <div className="tf-chart">
              <div className="tf-top">
                <span className="din iso">
                  <Sk as="b" w={90} style={{ display: 'inline-block' }} />
                </span>
                <span className="dout iso">
                  <Sk as="b" w={90} style={{ display: 'inline-block' }} />
                </span>
              </div>
              <Box w="100%" h={46} r={8} />
            </div>
            <div className="ttiles">
              {[0, 1].map((i) => (
                <div className="ttile" key={i}>
                  <span className="din">
                    <Sk w={60} style={{ display: 'inline-block' }} />
                  </span>
                  <Sk as="b" w={84} />
                </div>
              ))}
            </div>
          </div>
        </OvSection>
      </div>

      <OvSection icon="grid" titleKey="ov_allnodes">
        <div className="otiles">
          {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
            <div className="otile" key={i}>
              <Sk w={i % 3 ? 88 : 120} />
              <Sk w={64} />
              <Box w="100%" h={6} r={3} />
            </div>
          ))}
        </div>
      </OvSection>

      <div className="ogrid">
        <OvSection icon="server" titleKey="ov_central">
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
        </OvSection>

        <OvSection icon="activity" titleKey="ov_worst">
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
        </OvSection>

        <OvSection icon="link" titleKey="ov_tunbreak">
          <div className="card">
            <div className="tst">
              {[0, 1, 2, 3].map((i) => (
                <div className="tb" key={i}>
                  <Sk as="div" className="n" w={36} style={{ margin: '0 auto' }} />
                  <Sk as="div" className="l" w={50} style={{ margin: '0 auto' }} />
                </div>
              ))}
            </div>
            <Box w="100%" h={12} r={20} style={{ marginTop: 12 }} />
            <div className="typleg">
              <Sk w={64} />
              <Sk w={64} />
            </div>
          </div>
        </OvSection>

        <OvSection icon="clock" titleKey="ov_uptime">
          <div className="ostat2">
            {[0, 1].map((i) => (
              <div className="card" key={i}>
                <Sk as="div" className="big" w={70} style={{ borderRadius: 6 }} />
                <Sk as="div" className="muted" w={120} />
              </div>
            ))}
          </div>
        </OvSection>
      </div>
    </>
  )
}

export function ApiCardSkeleton() {
  return (
    <div className="card opc">
      <div className="ophd">
        <Box w={30} h={30} r={9} />
        <span className="hd2">
          <Sk as="b" w={150} />
          <Sk as="small" w={130} />
        </span>
        <Box w={44} h={25} r={14} />
      </div>
      <div className="oprow">
        <Box h="var(--sc-h)" r={10} style={{ flex: 1 }} />
        <Box w={110} h="var(--sc-h)" r={10} />
      </div>
    </div>
  )
}

export function SettingsSkeleton() {
  return (
    <div className="card sg">
      {SETTINGS_GROUPS.map(([tone, rows]) => (
        <section className={'sgsec ' + tone} key={tone}>
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
        </section>
      ))}
    </div>
  )
}
