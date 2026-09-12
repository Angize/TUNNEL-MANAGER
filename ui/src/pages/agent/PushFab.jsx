import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

const FINISHED = ['ok', 'same', 'err', 'skip']

export default function PushFab({ state, onPause, onResume, onCancel }) {
  if (!state || state.done) return null

  const nodes = state.nodes || {}
  const order = state.order || []
  const done = order.filter((id) => FINISHED.includes((nodes[id] || {}).state)).length
  const paused = !!state.paused
  const stoppable = order.some((id) => {
    const s = (nodes[id] || {}).state
    return s === 'wait' || s === 'run'
  })

  return (
    <div className="pfab">
      <span className="pfn">
        {num(done)}
        <s>/{num(order.length)}</s>
      </span>
      <button className="pfb" disabled={paused} title={T('ag_p_pause')} onClick={onPause}>
        <Icon name="pause" />
      </button>
      <button className="pfb" disabled={!paused} title={T('ag_p_resume')} onClick={onResume}>
        <Icon name="play" />
      </button>
      <button
        className="pfb stop"
        disabled={!stoppable}
        title={T(stoppable ? 'ag_p_cancel' : 'ag_p_cancel_none')}
        onClick={onCancel}
      >
        <Icon name="xc" />
      </button>
    </div>
  )
}
