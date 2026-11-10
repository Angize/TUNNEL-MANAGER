import { useEffect, useState } from 'react'
import { T } from '../i18n/fa.js'
import { CDN_PAGE_KEY, getLS } from '../lib/storage.js'
import './skeleton.css'

const MAX_CARDS = 6
const TUNNEL_KPI = 2
const LOG_ROWS = 5
const CHIPS = [84, 124, 83]
const SHOW_DELAY = 180
const FADE_MS = 300
const CARRY_MS = 100
const SHOWN = { animation: 'none' }

export const SKEL_ROWS = {
  values: [5, 3],
  apiForm: [1],
  apiDocs: [6],
  cdnCloud: [3, 3],
  cdnEdge: [3],
  upkeep: [4, 3],
}

let bootLive = 0
let bootSince = 0
let bootLeft = -Infinity

const range = (n) => Array.from({ length: n }, (_, i) => i)

function entrance(boot) {
  const now = performance.now()
  if (!bootLive && now - bootLeft > CARRY_MS) {
    if (boot) bootSince = now
    return undefined
  }
  const shown = now - bootSince
  if (shown >= SHOW_DELAY + FADE_MS) return SHOWN
  return { animationDelay: SHOW_DELAY - shown + 'ms' }
}

export function skelCount(summary, key) {
  if (!summary || !summary.loaded) return 3
  return Math.min(Math.max(summary.counts[key] || 0, 1), MAX_CARDS)
}

function Bone({ w, h, r, cls }) {
  return <i className={'skb' + (cls ? ' ' + cls : '')} style={{ inlineSize: w, blockSize: h, borderRadius: r }} />
}

export function SkelZone({ boot, className, children }) {
  const [style] = useState(() => entrance(boot))
  const [said, setSaid] = useState(false)

  useEffect(() => {
    if (boot) bootLive += 1
    const t = setTimeout(() => setSaid(true), SHOW_DELAY)
    return () => {
      clearTimeout(t)
      if (!boot) return
      bootLive -= 1
      bootLeft = performance.now()
    }
  }, [boot])

  return (
    <div className={'skz' + (className ? ' ' + className : '')} style={style} role="status">
      <span className="skhide">{said ? T('loading') : ''}</span>
      <div aria-hidden="true">{children}</div>
    </div>
  )
}

function SkelTitle({ sub }) {
  return (
    <>
      <div className="skh1">
        <Bone w={23} h={23} r={7} />
        <Bone w={118} h={17} />
      </div>
      {sub ? (
        <div className="sub skp">
          <Bone w="58%" h={10} />
        </div>
      ) : null}
    </>
  )
}

function SkelHub({ tabs }) {
  return (
    <>
      <SkelTitle />
      <div className="lseg skseg">
        {range(tabs).map((i) => (
          <span key={i}>
            <Bone w="44%" h={10} />
          </span>
        ))}
      </div>
      <div className="ldots">
        {range(tabs).map((i) => (
          <i key={i} />
        ))}
      </div>
      <div className="sub lsub skp">
        <Bone w="64%" h={10} />
      </div>
    </>
  )
}

function SkelTools({ buttons, lead, search = true }) {
  return (
    <>
      <div className={'tbtnrow' + (lead ? ' skbtns' : '')}>
        {range(buttons).map((i) => (
          <Bone key={i} w={i ? 104 : 116} h={40} r={14} />
        ))}
      </div>
      {search ? (
        <div className="toolbar">
          <Bone w="100%" h={42} r={14} />
        </div>
      ) : null}
    </>
  )
}

export function SkelHeads({ n }) {
  return (
    <div className="flist">
      {range(n).map((i) => (
        <div key={i} className="card skc skhead">
          <Bone w={34} h={20} r={10} />
          <Bone w="30%" h={11} />
          <Bone w={38} h={16} r={6} />
          <span className="skgap" />
          <Bone w={14} h={14} r={7} />
        </div>
      ))}
    </div>
  )
}

export function SkelNodes({ n }) {
  return (
    <div className="flist">
      {range(n).map((i) => (
        <div key={i} className="card skc sknode">
          <div className="skrow">
            <Bone w={10} h={10} r={5} />
            <Bone w="34%" h={12} />
            <Bone w={46} h={16} r={6} />
            <span className="skgap" />
            <Bone w={14} h={14} r={7} />
          </div>
          <Bone w="62%" h={10} />
          <Bone w="44%" h={10} />
        </div>
      ))}
    </div>
  )
}

export function SkelLogs() {
  return (
    <>
      <div className="logchips">
        {CHIPS.map((w) => (
          <Bone key={w} w={w} h={40} r={999} />
        ))}
      </div>
      <div className="loglist">
        {range(LOG_ROWS).map((i) => (
          <div key={i} className="skc sklev">
            <i className="skstrip" />
            <div>
              <div className="skrow">
                <Bone w={34} h={10} />
                <Bone w={92} h={10} />
              </div>
              <Bone w="86%" h={11} />
              <Bone w="54%" h={11} cls="l2" />
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

export function SkelKpis({ note }) {
  return (
    <div className="okpis">
      {range(4).map((i) => (
        <div key={i} className="card okpi skc skkpi">
          <Bone w="48%" h={10} />
          <Bone w="34%" h={26} r={8} />
          {note && i === TUNNEL_KPI ? <Bone w="58%" h={9} cls="sknote" /> : null}
        </div>
      ))}
    </div>
  )
}

function SkelSec({ children }) {
  return (
    <section className="osec">
      <div className="sec sksec">
        <Bone w={96} h={11} />
      </div>
      {children}
    </section>
  )
}

export function SkelOverview() {
  return (
    <div className="ogrid oduo">
      <SkelSec>
        <div className="card skc skov1">
          <Bone w={16} h={16} r={8} />
          <Bone w="44%" h={11} />
        </div>
      </SkelSec>
      <SkelSec>
        <div className="card skc skov2">
          <div className="skrow">
            <Bone w={72} h={16} />
            <Bone w={72} h={16} />
          </div>
          <div className="skrow">
            {range(5).map((i) => (
              <Bone key={i} w={46} h={12} />
            ))}
          </div>
          <Bone w="100%" r={12} cls="skchart" />
        </div>
      </SkelSec>
    </div>
  )
}

export function SkelBlocks({ rows }) {
  return rows.map((n, i) => <SkelBlock key={i} rows={n} />)
}

function SkelBlock({ rows }) {
  return (
    <div className="card skc skblock">
      <div className="skrow">
        <Bone w={30} h={30} r={9} />
        <Bone w="36%" h={12} />
      </div>
      {range(rows).map((i) => (
        <div key={i} className="skrow skline">
          <Bone w="38%" h={10} />
          <span className="skgap" />
          <Bone w="30%" h={38} r={12} />
        </div>
      ))}
    </div>
  )
}

export function SkelGrid({ n }) {
  return (
    <div className="skgrid">
      {range(n).map((i) => (
        <div key={i} className="skc sknx">
          <div className="skrow">
            <Bone w={10} h={10} r={5} />
            <Bone w="46%" h={11} />
          </div>
          <Bone w="70%" h={10} />
          <Bone w="52%" h={10} />
          <span className="skgap" />
          <Bone w="100%" h={34} r={11} />
        </div>
      ))}
    </div>
  )
}

export function SkelForm() {
  return (
    <SkelZone className="skc">
      <div className="skform">
        {range(3).map((i) => (
          <div key={i} className="skfld">
            <Bone w={i ? '26%' : '34%'} h={10} />
            <Bone w="100%" h={42} r={12} />
          </div>
        ))}
      </div>
    </SkelZone>
  )
}

function SettingsBody({ kind }) {
  if (kind === 'set-values') return <SkelBlocks rows={SKEL_ROWS.values} />
  if (kind === 'set-api') return <SkelBlocks rows={[...SKEL_ROWS.apiForm, ...SKEL_ROWS.apiDocs]} />
  if (kind !== 'set-cdn') return <SkelBlocks rows={SKEL_ROWS.upkeep} />
  const edge = getLS(CDN_PAGE_KEY) === 'cdn-edge'
  return (
    <>
      <div className="lseg nested skseg">
        {range(2).map((i) => (
          <span key={i}>
            <Bone w="44%" h={10} />
          </span>
        ))}
      </div>
      <SkelBlocks rows={edge ? SKEL_ROWS.cdnEdge : SKEL_ROWS.cdnCloud} />
    </>
  )
}

export function PageSkeleton({ page, kind, tabs, count, summary }) {
  if (page === 'overview') {
    return (
      <SkelZone boot>
        <SkelTitle sub />
        <SkelKpis note={summary.tunNote} />
        <SkelOverview />
      </SkelZone>
    )
  }
  if (page === 'logs') {
    return (
      <SkelZone boot>
        <SkelTitle />
        <SkelTools buttons={2} />
        <SkelLogs />
      </SkelZone>
    )
  }
  if (page === 'settings') {
    return (
      <SkelZone boot>
        <SkelHub tabs={tabs} />
        <SettingsBody kind={kind} />
      </SkelZone>
    )
  }
  return (
    <SkelZone boot>
      <SkelHub tabs={tabs} />
      <SkelTools lead buttons={page === 'links' && kind !== 'portfw' ? 2 : 1} search={kind !== 'proxies'} />
      {kind === 'nodes' ? <SkelNodes n={skelCount(summary, count)} /> : <SkelHeads n={skelCount(summary, count)} />}
    </SkelZone>
  )
}
