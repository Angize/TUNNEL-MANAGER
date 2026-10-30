import { EdgeRow } from './WsPool.jsx'
import { StaleCap } from './HealthRow.jsx'
import useSecondTick from './useSecondTick.js'
import { T } from '../../../i18n/fa.js'

function rowsOf(status) {
  const rows = Object.keys(status.live).map((id) => {
    const at = id.indexOf(':')
    return { id, kind: id.slice(0, at), key: id.slice(at + 1), health: status.live[id] }
  })
  const edges = rows.filter((r) => r.kind === 'sni')
  return rows.filter((r) => r.kind === 'ip').concat(edges.length > 1 ? edges : [])
}

export default function EdgeLive({ live, lid }) {
  const { status, pending } = live
  useSecondTick(true)
  const rows = rowsOf(status)

  return (
    <div className="peerlive">
      <div className="pllabel">{T('peer_live_hd')}</div>
      <StaleCap status={status} />
      {rows.length ? (
        <div className="elist">
          {rows.map((r) => (
            <EdgeRow
              key={r.id}
              value={r.key}
              label={r.health.label}
              kind={r.kind}
              health={r.health}
              active={status.act[r.kind] === r.key}
              lid={lid}
              pending={pending}
              status={status}
              onRetest={live.retest}
              onSelect={live.select}
            />
          ))}
        </div>
      ) : (
        <div className="fldhint">{T('peer_live_empty')}</div>
      )}
    </div>
  )
}
