import Icon from '../../../components/Icon.jsx'
import RichText from '../../../components/RichText.jsx'
import { ScrollSeg, SegOpt } from './controls.jsx'
import { intOf } from './validate.js'
import { cfWantsRule } from '../../../lib/cdn.js'
import { faNum } from '../../../lib/num.js'
import { T, TF } from '../../../i18n/fa.js'

const ICON = { ok: 'okc', gold: 'info', no: 'warn' }

function used(info) {
  return info.rules.length + info.hand
}

function full(info) {
  return !!info.cap && used(info) >= info.cap
}

function room(info) {
  return !info.cap || used(info) - info.freed < info.cap
}

function ruled(info, port) {
  return info.rules.some((r) => r.port === port)
}

function fits(infos, port) {
  return infos.every((i) => ruled(i, port) || room(i))
}

function ports(infos) {
  const seen = new Map()
  for (const info of infos) for (const r of info.rules) seen.set(r.port, (seen.get(r.port) || 0) + 1)
  return [...seen].sort((a, b) => b[1] - a[1] || a[0] - b[0])
}

function names(infos) {
  return infos.map((i) => i.zone).join('، ')
}

function fills(infos, count) {
  return infos.map((i) => TF('cpr_count', { u: faNum(count(i)), c: faNum(i.cap) })).join('؛ ')
}

function slot(v) {
  return v.next.some((i) => !i.cap) ? { ...v, kind: v.kind + '_x' } : { ...v, f: fills(v.next, (i) => used(i) - i.freed + 1) }
}

export function autoPort(infos) {
  if (!infos) return 0
  const taken = infos[0].taken
  const fit = ports(infos).find(([p]) => !taken[p] && fits(infos, p))
  return fit ? fit[0] : 0
}

function portVerdict(infos, port, tls) {
  const taken = infos[0].taken
  const many = infos.length > 1
  if (!port) {
    const p = autoPort(infos)
    if (p) {
      const miss = infos.filter((i) => !ruled(i, p))
      if (!miss.length) return { kind: many ? 'auto_join_all' : 'auto_join', tone: 'ok', p, n: infos.length }
      return slot({ kind: 'auto_part', tone: 'gold', p, z: names(miss), next: miss })
    }
    const blocked = infos.filter((i) => !room(i))
    if (blocked.length) return { kind: 'auto_full', tone: 'no', z: names(blocked) }
    return slot({ kind: 'auto_new', tone: 'gold', next: infos })
  }
  if (taken[port]) return { kind: 'taken', tone: 'no', p: port, t: taken[port] }
  if (!cfWantsRule(port, tls)) return { kind: 'none', tone: 'ok', p: port }
  const miss = infos.filter((i) => !ruled(i, port))
  const blocked = miss.filter((i) => !room(i))
  if (blocked.length) return { kind: 'full', tone: 'no', p: port, z: names(blocked), f: fills(blocked, used) }
  if (!miss.length) return { kind: many ? 'join_all' : 'join', tone: 'ok', p: port, n: infos.length }
  return slot({ kind: many ? 'new_some' : 'new', tone: 'gold', p: port, z: names(miss), next: miss })
}

function Meter({ info, next, many }) {
  const panel = info.rules.length
  const n = used(info)
  const free = Math.max(0, info.cap - n)
  const take = next && free && !info.freed ? 1 : 0
  const [before, after] = T('cpr_head').split('{z}')
  const parts = [
    ['cp', panel],
    ['ch', info.hand],
    ['cn', take],
    ['', free - take],
  ].filter(([, k]) => k > 0)

  return (
    <div className="cprmeter">
      <div className="cprtop">
        <span className="cprhead">
          {many ? null : before}
          <span className="mono" dir="ltr">
            {info.zone}
          </span>
          {many ? null : after}
        </span>
        <b className={'cprcount' + (full(info) ? ' full' : '')}>
          {TF('cpr_count', { u: faNum(n), c: faNum(info.cap) })}
        </b>
      </div>
      <div className="cprbar" aria-hidden="true">
        {parts.map(([cls, k]) => (
          <i key={cls || 'free'} className={cls || undefined} style={{ flexGrow: k }} />
        ))}
      </div>
      <div className="cprlegend">
        <span>
          <i className="cp" aria-hidden="true" />
          {TF('cpr_legend_panel', { n: faNum(panel) })}
        </span>
        {info.hand ? (
          <span>
            <i className="ch" aria-hidden="true" />
            {TF('cpr_legend_hand', { n: faNum(info.hand) })}
          </span>
        ) : null}
        <span>
          <i aria-hidden="true" />
          {TF('cpr_legend_free', { n: faNum(free) })}
        </span>
      </div>
    </div>
  )
}

function chipOff(infos, port) {
  if (infos[0].taken[port]) return 'cpr_here'
  return fits(infos, port) ? '' : 'cpr_nofit'
}

function chipSub(infos, port, hits) {
  if (infos.length === 1) return TF('cpr_hosts', { n: faNum(infos[0].rules.find((r) => r.port === port).hosts.length) })
  return hits === infos.length ? T('cpr_in_all') : TF('cpr_in_some', { n: faNum(hits), m: faNum(infos.length) })
}

export default function CdnPortRules({ infos, port, tls, bad, onPick }) {
  if (!infos) return null
  const typed = intOf(port)
  const v = bad ? null : portVerdict(infos, typed, tls)
  const next = new Set(v && v.next ? v.next.map((i) => i.zone) : [])
  const many = infos.length > 1
  const list = ports(infos)

  return (
    <div className="cpr">
      {v ? (
        <div className={'warncap ' + v.tone} role="status">
          <Icon name={ICON[v.tone]} />
          <span>
            <RichText text={TF('cpr_' + v.kind, { p: v.p, t: v.t, z: v.z, n: v.n && faNum(v.n), f: v.f })} />
          </span>
        </div>
      ) : null}
      {many ? <div className="cprpick">{TF('cpr_zones', { n: faNum(infos.length) })}</div> : null}
      {infos.map((info) => (info.cap ? <Meter key={info.zone} info={info} next={next.has(info.zone)} many={many} /> : null))}
      {list.length ? (
        <>
          <div className="cprpick">{T('cpr_pick')}</div>
          <ScrollSeg label={T('cpr_pick')}>
            {list.map(([p, hits]) => {
              const off = chipOff(infos, p)
              return (
                <SegOpt
                  key={p}
                  on={typed === p}
                  title={String(p)}
                  sub={off ? T(off) : chipSub(infos, p, hits)}
                  disabled={!!off}
                  onClick={() => onPick(String(p))}
                />
              )
            })}
          </ScrollSeg>
        </>
      ) : null}
    </div>
  )
}
