import { T, TF } from '../../i18n/fa.js'
import { WARN_PCT, usageLevel } from '../../lib/health.js'
import { num } from '../../lib/num.js'
import { setPageQuery } from '../../lib/pageQuery.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import StatusGroups from './StatusGroups.jsx'

const METRIC = { cpu: () => 'CPU', ram: () => T('ram'), disk: () => T('disk') }

function nodeGroup(node, crit) {
  if (node.disabled) return 'dis'
  if (node.online) return usageLevel(num(node.pct), crit)
  if (node.pending) return 'wait'
  return 'off'
}

export default function NodeGroups({ heat, onNavigate }) {
  const crit = num(useUiConfig().usage_crit_pct)

  if (!heat.length) {
    return (
      <div className="card">
        <div className="muted otnote">{T('ov_no_nodes')}</div>
      </div>
    )
  }

  const by = { crit: [], off: [], warn: [], wait: [], ok: [], dis: [] }
  for (const node of heat) by[nodeGroup(node, crit)].push(node)
  for (const list of Object.values(by)) list.sort((a, b) => num(b.pct) - num(a.pct))

  const row = (node) => {
    const level = node.online ? usageLevel(num(node.pct), crit) : ''
    return (
      <button
        key={node.name}
        type="button"
        className="sgr"
        onClick={() => onNavigate('nodes', () => setPageQuery('nodes', '"' + node.name + '"'))}
      >
        <span className="sgn" dir="ltr">
          {node.name}
        </span>
        {node.online ? (
          <>
            <span className="sgbar">
              <i className={level} style={{ width: num(node.pct) + '%' }} />
            </span>
            <span className="sgm">{METRIC[node.met] ? METRIC[node.met]() : ''}</span>
            <b className={'sgv ' + level}>{num(node.pct) + T('pct')}</b>
          </>
        ) : (
          <span className="sgs">{T(node.disabled ? 'ov_node_disabled' : node.pending ? 'pending_check' : 'offline')}</span>
        )}
      </button>
    )
  }

  const top = by.ok
    .slice(0, 3)
    .map((n) => (
      <span key={n.name}>
        <bdi>{n.name}</bdi> <b>{num(n.pct) + T('pct')}</b>
      </span>
    ))

  return (
    <div className="card">
      <StatusGroups
        groups={[
          { key: 'crit', tone: 'bad', title: T('st_crit'), hint: TF('st_from', { n: crit }), items: by.crit, row, open: true },
          { key: 'off', tone: 'bad', title: T('offline'), items: by.off, row, open: true },
          { key: 'warn', tone: 'warn', title: T('st_warn'), hint: TF('st_from', { n: WARN_PCT }), items: by.warn, row, open: true },
          { key: 'wait', tone: 'mute', title: T('pending_check'), items: by.wait, row },
          {
            key: 'ok',
            tone: 'ok',
            title: T('st_healthy'),
            items: by.ok,
            row,
            preview: top.length ? (
              <>
                <small>{T('st_top')}</small>
                {top}
              </>
            ) : null,
          },
          { key: 'dis', tone: 'mute', title: T('ov_node_disabled'), items: by.dis, row },
        ]}
      />
      <div className="muted otnote">{TF('ov_tiles_note', { n: heat.length })}</div>
    </div>
  )
}
