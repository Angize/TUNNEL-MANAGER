import { T, TF } from '../../i18n/fa.js'
import { usageColor, usageLevel } from '../../lib/health.js'
import { num } from '../../lib/num.js'
import { setPageQuery } from '../../lib/pageQuery.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const STATES = {
  online: { word: 'online', color: 'var(--ok-tx)' },
  offline: { word: 'offline', color: 'var(--bad-tx)' },
  disabled: { word: 'ov_node_disabled', color: 'var(--sub)' },
  checking: { word: 'pending_check', color: 'var(--sub)' },
}

function nodeState(node) {
  if (node.disabled) return 'disabled'
  if (node.online) return 'online'
  if (node.pending) return 'checking'
  return 'offline'
}

function NodeTile({ node, crit, onOpen }) {
  const state = nodeState(node)
  const { word, color } = STATES[state]
  const pct = num(node.pct)

  return (
    <button type="button" className={'otile' + (state === 'disabled' ? ' off' : '')} onClick={onOpen}>
      <span className="otn">{node.name}</span>
      <span className="ots">
        <span className="otw" style={{ color }}>
          <i className="dot" style={{ background: color }} />
          {T(word)}
        </span>
        <b className="otp" style={{ color: node.online ? usageColor(pct, crit) : undefined }}>
          {node.online ? pct + T('pct') : '—'}
        </b>
      </span>
      <span className="otb">
        {node.online ? <i className={usageLevel(pct, crit)} style={{ width: pct + '%' }} /> : null}
      </span>
    </button>
  )
}

export default function NodeHeat({ heat, onNavigate }) {
  const crit = num(useUiConfig().usage_crit_pct)

  if (!heat.length) {
    return (
      <div className="card">
        <div className="muted otnote">{T('ov_no_nodes')}</div>
      </div>
    )
  }

  return (
    <>
      <div className="otiles">
        {heat.map((node) => (
          <NodeTile
            key={node.name}
            node={node}
            crit={crit}
            onOpen={() => onNavigate('nodes', () => setPageQuery('nodes', '"' + node.name + '"'))}
          />
        ))}
      </div>
      <div className="heat-lg">
        <span>
          <i style={{ background: 'var(--ok)' }} />
          {T('st_healthy')}
        </span>
        <span>
          <i style={{ background: 'var(--gold)' }} />
          {T('st_warn')}
        </span>
        <span>
          <i style={{ background: 'var(--bad)' }} />
          {TF('st_crit', { n: crit })}
        </span>
      </div>
      <div className="muted otnote">{TF('ov_tiles_note', { n: heat.length })}</div>
    </>
  )
}
