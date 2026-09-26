import { useEffect, useRef, useState } from 'react'
import { T, TF } from '../../i18n/fa.js'
import { usageColor } from '../../lib/health.js'
import { num } from '../../lib/num.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const TIP_MS = 2400

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

function NodeTile({ node, crit, tip, onTip }) {
  const state = nodeState(node)
  const { word, color } = STATES[state]
  const pct = num(node.pct)
  const metricColor = node.online ? usageColor(pct, crit) : undefined
  const metric = node.online ? pct + T('pct') : null

  return (
    <button
      type="button"
      className={'otile' + (state === 'disabled' ? ' off' : '')}
      onClick={(e) => onTip(e, node.name)}
    >
      <span className="otn">{node.name}</span>
      <span className="ots">
        <span className="otw" style={{ color }}>
          <i className="dot" style={{ background: color }} />
          {T(word)}
        </span>
        <b className="otp" style={{ color: metricColor }}>
          {metric || '—'}
        </b>
      </span>
      <span className="otb">
        {node.online ? <i style={{ width: pct + '%', background: metricColor }} /> : null}
      </span>
      {tip ? (
        <span className="htip" aria-hidden="true">
          <span>{node.name}</span> {metric || T(word)}
        </span>
      ) : null}
    </button>
  )
}

export default function NodeHeat({ heat }) {
  const crit = num(useUiConfig().usage_crit_pct)
  const [tip, setTip] = useState(null)
  const timer = useRef(0)

  useEffect(() => () => clearTimeout(timer.current), [])

  const showTip = (event, name) => {
    event.stopPropagation()
    setTip(name)
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setTip(null), TIP_MS)
  }

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
          <NodeTile key={node.name} node={node} crit={crit} tip={tip === node.name} onTip={showTip} />
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
          {T('st_crit')}
        </span>
      </div>
      <div className="muted otnote">{TF('ov_tiles_note', { n: heat.length })}</div>
    </>
  )
}
