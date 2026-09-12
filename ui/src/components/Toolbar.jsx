import { useEffect, useRef, useState } from 'react'
import { GripIcon } from './Grip.jsx'
import { toggleReorder } from '../lib/reorder.js'
import { T } from '../i18n/fa.js'

const DEBOUNCE = 280

export default function Toolbar({ value, placeholder, reorder, onSearch }) {
  const [text, setText] = useState(value || '')
  const timer = useRef(0)

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
        placeholder={placeholder}
        value={text}
        onChange={(e) => change(e.target.value)}
      />
      {reorder ? (
        <button className="reordbtn" title={T('reord_t')} onClick={toggleReorder}>
          <GripIcon />
        </button>
      ) : null}
    </div>
  )
}
