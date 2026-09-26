import { useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'
import usePresence from '../../lib/usePresence.js'

const FINISHED = ['ok', 'same', 'err', 'skip']
const EXIT_MS = 180

export default function PushFab({ state, onPause, onResume, onCancel }) {
  const visible = !!(state && !state.done)
  const shown = usePresence(visible, EXIT_MS)
  const [kept, setKept] = useState(state)
  if (visible && state !== kept) setKept(state)
  if (!shown) return null
  return (
    <Fab
      state={visible ? state : kept}
      leaving={!visible}
      onPause={onPause}
      onResume={onResume}
      onCancel={onCancel}
    />
  )
}

function Fab({ state, leaving, onPause, onResume, onCancel }) {

  const nodes = state.nodes || {}
  const order = state.order || []
  const done = order.filter((id) => FINISHED.includes((nodes[id] || {}).state)).length
  const paused = !!state.paused
  const stoppable = order.some((id) => {
    const s = (nodes[id] || {}).state
    return s === 'wait' || s === 'run'
  })

  return createPortal(
    <div className={'pfab' + (leaving ? ' out' : '')} inert={leaving}>
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
    </div>,
    document.body
  )
}
