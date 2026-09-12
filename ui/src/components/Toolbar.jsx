import { useEffect, useRef, useState } from 'react'

const DEBOUNCE = 280

export default function Toolbar({ value, placeholder, onSearch }) {
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
    </div>
  )
}
