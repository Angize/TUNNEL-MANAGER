import { useId, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Reveal from '../../components/Reveal.jsx'
import { edgeHost } from './carrier.js'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { providerName } from '../../lib/cdn.js'
import { faNum } from '../../lib/num.js'
import { T, TF } from '../../i18n/fa.js'

const ICON = { ok: 'okc', bad: 'warn', wait: 'clock' }
const CHIP = { ok: 'ok', bad: 'bad', wait: 'run' }

function toneOf(state) {
  return state.ok ? 'ok' : state.error ? 'bad' : 'wait'
}

function cdnView(cdn) {
  const hosts = cdn.pool ? cdn.hosts || [] : []
  const tones = cdn.pool ? hosts.map(toneOf) : [toneOf(cdn)]
  const tone = tones.includes('bad') ? 'bad' : tones.includes('wait') ? 'wait' : 'ok'
  const providers = [...new Set(cdn.pool ? hosts.map((h) => h.provider) : [cdn.provider])]
  const names = providers.map(providerName).join(T('px_and'))
  const pill = cdn.pool
    ? TF('cdn_pill_pool', { p: names, ok: faNum(hosts.filter((h) => h.ok).length), n: faNum(hosts.length) })
    : TF('cdn_pill', { p: names, s: T('cdn_own_' + tone) })
  return { tone, hosts, providers, names, pill }
}

function edgeView(link, activeEdge) {
  if (link.transport !== 'ws') return null
  if (link.ws_pool) {
    if (link.enabled === false) return null
    const parts = String(activeEdge || '').split(' · ')
    return { live: true, ip: edgeHost(parts[0] || ''), domain: parts.slice(1).join(' · ') }
  }
  const ip = link.edge_ip ? edgeHost(link.edge_ip) : ''
  const domain = link.ws_host || ''
  return ip || domain ? { live: false, ip, domain } : null
}

function EdgeChips({ ip, domain }) {
  if (!ip && !domain) return <span className="echip wait">…</span>
  return (
    <>
      {ip ? <span className="echip ip">{ip}</span> : null}
      {domain ? <span className="echip dom">{domain}</span> : null}
    </>
  )
}

function CdnError({ state, ip }) {
  const live = state.applied && state.applied.ip && state.applied.ip !== ip ? state.applied.ip : ''
  return (
    <div className="cdxerr">
      <Icon name="warn" />
      <div className="cdxerrt">
        <p>{translateError(state.error)}</p>
        {live ? <p className="cdxnow">{TF('cdn_own_live', { ip: live })}</p> : null}
      </div>
    </div>
  )
}

function PoolHosts({ hosts, ip }) {
  return (
    <>
      <p className="cdxcap">{T('cdn_pool_hosts')}</p>
      <ul className="cdxhosts">
        {hosts.map((h) => {
          const tone = toneOf(h)
          return (
            <li key={h.host} className={tone}>
              <Icon name={ICON[tone]} />
              <span className="cdxhn mono" dir="ltr">
                {h.host}
              </span>
              {tone === 'ok' ? null : <span className={'cdnchip ' + CHIP[tone]}>{T('cdn_own_' + tone)}</span>}
              {tone === 'bad' ? <CdnError state={h} ip={ip} /> : null}
            </li>
          )
        })}
      </ul>
    </>
  )
}

function Row({ label, tag, value }) {
  return (
    <div>
      <dt>
        {label}
        {tag ? <small>{tag}</small> : null}
      </dt>
      <dd dir="ltr" className="mono">
        {value}
      </dd>
    </div>
  )
}

function portTag(providers) {
  if (providers.length !== 1) return ''
  return T(providers[0] === 'cf' ? 'cdn_port_rule' : 'cdn_port_rec')
}

function Drawer({ link, cdn, view, onReload }) {
  const { tone, hosts, providers, names } = view
  const [pick, setPick] = useState({ tone, open: tone === 'bad' })
  const [busy, setBusy] = useState(false)
  const id = useId()
  const pool = !!cdn.pool
  if (pick.tone !== tone) setPick({ tone, open: tone === 'bad' })
  const open = pick.tone === tone ? pick.open : tone === 'bad'

  const sync = async () => {
    setBusy(true)
    const r = await apiPost('cdn-sync', { id: link.id })
    setBusy(false)
    if (r.ok && r.d.ok) toast(T('cdn_synced'), 'ok')
    else toast(postError(r), 'err')
    onReload()
  }

  return (
    <>
      <button
        type="button"
        className="cdxdrw"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setPick({ tone, open: !open })}
      >
        <span className={'cdxcloud' + (providers.length === 1 ? ' ' + providers[0] : '')}>
          <Icon name="cloud" />
        </span>
        <span className="cdxdrt">{TF('cdn_more', { p: names })}</span>
        <span className="cdxdrs">{T('cdn_by_panel')}</span>
        <span className="cdxchev">
          <Icon name="chev" />
        </span>
      </button>
      <div id={id}>
        <Reveal show={open}>
          <div className="cdxin">
            {tone === 'wait' ? (
              <p className="cdxwait">
                <Icon name="clock" />
                <span>{T('cdn_wait_d') + ' ' + T('cdn_own_auto')}</span>
              </p>
            ) : null}
            {pool ? <PoolHosts hosts={hosts} ip={cdn.ip} /> : null}
            {!pool && tone === 'bad' ? <CdnError state={cdn} ip={cdn.ip} /> : null}
            <dl className="cdxkv">
              {pool ? null : <Row label={T('cdn_own_host')} value={cdn.host} />}
              <Row label={T('cdn_own_ip')} value={cdn.ip} />
              {cdn.port ? <Row label={T('cdn_own_port')} tag={portTag(providers)} value={cdn.port} /> : null}
            </dl>
            {tone === 'bad' ? (
              <div className="cdxact">
                <button type="button" className="ghost tone tone-renew cdxretry" disabled={busy} onClick={sync}>
                  <Icon name="redo" />
                  {T(busy ? 'cdn_syncing' : 'cdn_retry')}
                </button>
                <span className="cdxauto">{T('cdn_own_auto')}</span>
              </div>
            ) : null}
          </div>
        </Reveal>
      </div>
    </>
  )
}

export default function CdnEdge({ link, activeEdge, onReload }) {
  const edge = edgeView(link, activeEdge)
  const cdn = link.cdn
  if (!edge && !cdn) return null
  const live = !!(edge && edge.live)
  const view = cdn ? cdnView(cdn) : null

  return (
    <div className={'cedge' + (live ? ' live' : '') + (view && view.tone === 'bad' ? ' cdxbad' : '')}>
      <div className="cedgef">
        <div className="ct">
          {live ? <span className="cdot" /> : null}
          <span className="ctt">{T(live ? 'active_edge' : 'cdn_edge')}</span>
          {view ? (
            <span className={'cdnchip cdxpill ' + CHIP[view.tone]}>
              <Icon name={ICON[view.tone]} />
              <span>{view.pill}</span>
            </span>
          ) : null}
        </div>
        {edge ? (
          <div className="echips">
            <EdgeChips ip={edge.ip} domain={edge.domain} />
          </div>
        ) : null}
      </div>
      {view ? <Drawer link={link} cdn={cdn} view={view} onReload={onReload} /> : null}
    </div>
  )
}
