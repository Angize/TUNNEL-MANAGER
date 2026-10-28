import Icon from '../../components/Icon.jsx'
import { movedTo } from './sideHealth.js'
import { T, TF } from '../../i18n/fa.js'

function heading(link, moved) {
  if (moved.length === 2) return T('drift_both')
  if (moved.length) return TF('drift_one', { a: link[moved[0][0] + '_name'] })
  return T(link.edge_stale ? 'drift_edge' : 'drift_any')
}

export default function DriftNote({ link, busy, locked, onRebuild }) {
  if (!link.drift) return null
  const moved = ['a', 'b'].map((side) => [side, movedTo(link, side)]).filter(([, now]) => now)

  return (
    <div className="driftbox" role="status">
      <Icon name="warn" />
      <b className="dbh">{heading(link, moved)}</b>
      <button type="button" className="ghost tone dbgo" disabled={locked} aria-busy={busy} onClick={onRebuild}>
        {busy ? <span className="bspin ink sm" /> : <Icon name="redo" />}
        {T('tip_rebuild')}
      </button>
      {moved.map(([side, now]) => (
        <span key={side} className="dbips">
          {moved.length > 1 ? <span className="dbn">{link[side + '_name']}</span> : null}
          <span className="dbip" dir="ltr">
            <span className="mono old">{link[side + '_ip']}</span>
            {now.length === 1 ? (
              <>
                <span aria-hidden="true">→</span>
                <span className="mono">{now[0]}</span>
              </>
            ) : null}
          </span>
        </span>
      ))}
    </div>
  )
}
