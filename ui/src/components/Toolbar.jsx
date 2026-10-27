import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { GripIcon } from './Grip.jsx'
import { reorderMode, subscribeReorder, toggleReorder } from '../lib/reorder.js'
import { T } from '../i18n/fa.js'

const DEBOUNCE = 280

export default function Toolbar({ value, placeholder, reorder, onSearch }) {
  const [text, setText] = useState(value || '')
  const timer = useRef(0)
  const lastValue = useRef(value)
  const sorting = useSyncExternalStore(subscribeReorder, reorderMode)

  if (lastValue.current !== value) {
    lastValue.current = value
    if ((value || '') !== text.trim()) setText(value || '')
  }

  useEffect(() => () => clearTimeout(timer.current), [])

  const change = (v) => {
    setText(v)
    clearTimeout(timer.current)
    timer.current = setTimeout(() => onSearch(v.trim()), DEBOUNCE)
  }

  return (
    <div className="toolbar">
      <input
        className="search"
        aria-label={placeholder}
        placeholder={placeholder}
        value={text}
        onChange={(e) => change(e.target.value)}
      />
      {reorder ? (
        <button
          className="reordbtn"
          title={T('reord_t')}
          aria-label={T('reord_t')}
          aria-pressed={sorting}
          onClick={toggleReorder}
        >
          <GripIcon />
        </button>
      ) : null}
    </div>
  )
}
