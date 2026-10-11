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

export function autoPort(info) {
  const free = info ? info.rules.find((r) => !info.taken[r.port]) : null
  return free ? free.port : 0
}

function portVerdict(info, port, tls) {
  if (!port) {
    const p = autoPort(info)
    if (p) return { kind: 'auto_join', tone: 'ok', p }
    if (full(info)) return { kind: 'auto_full', tone: 'no' }
    return { kind: 'auto_new', tone: 'gold', next: true }
  }
  if (info.taken[port]) return { kind: 'taken', tone: 'no', p: port, t: info.taken[port] }
  if (!cfWantsRule(port, tls)) return { kind: 'none', tone: 'ok', p: port }
  if (info.rules.some((r) => r.port === port)) return { kind: 'join', tone: 'ok', p: port }
  if (full(info)) return { kind: 'full', tone: 'no', p: port }
  return { kind: 'new', tone: 'gold', p: port, next: true }
}

function Meter({ info, next }) {
  const panel = info.rules.length
  const n = used(info)
  const [before, after] = T('cpr_head').split('{z}')
  const cells = Array.from({ length: info.cap }, (_, i) =>
    i < panel ? 'cp' : i < n ? 'ch' : i === n && next ? 'cn' : ''
  )

  return (
    <div className="cprmeter">
      <div className="cprtop">
        <span className="cprhead">
          {before}
          <span className="mono" dir="ltr">
            {info.zone}
          </span>
          {after}
        </span>
        <b className={'cprcount' + (full(info) ? ' full' : '')}>
          {TF('cpr_count', { u: faNum(n), c: faNum(info.cap) })}
        </b>
      </div>
      <div className="cprbar" aria-hidden="true">
        {cells.map((k, i) => (
          <i key={i} className={k || undefined} />
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
          {TF('cpr_legend_free', { n: faNum(Math.max(0, info.cap - n)) })}
        </span>
      </div>
    </div>
  )
}

export default function CdnPortRules({ info, port, tls, bad, onPick }) {
  if (!info) return null
  const typed = intOf(port)
  const v = bad ? null : portVerdict(info, typed, tls)
  const key = v ? 'cpr_' + v.kind + (v.next && !info.cap ? '_x' : '') : ''

  return (
    <div className="cpr">
      {v ? (
        <div className={'warncap ' + v.tone} role="status">
          <Icon name={ICON[v.tone]} />
          <span>
            <RichText text={TF(key, { p: v.p, t: v.t, u: faNum(used(info) + 1), c: faNum(info.cap) })} />
          </span>
        </div>
      ) : null}
      {info.cap ? <Meter info={info} next={!!(v && v.next)} /> : null}
      {info.rules.length ? (
        <>
          <div className="cprpick">{T('cpr_pick')}</div>
          <ScrollSeg label={T('cpr_pick')}>
            {info.rules.map((r) => (
              <SegOpt
                key={r.port}
                on={typed === r.port}
                title={String(r.port)}
                sub={info.taken[r.port] ? T('cpr_here') : TF('cpr_hosts', { n: faNum(r.hosts) })}
                disabled={!!info.taken[r.port]}
                onClick={() => onPick(String(r.port))}
              />
            ))}
          </ScrollSeg>
        </>
      ) : null}
    </div>
  )
}
