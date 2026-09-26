import { useRef, useState } from 'react'
import usePresence from '../lib/usePresence.js'
import './reveal.css'

const EXIT_MS = 260

export default function Reveal({ show, children }) {
  const shown = usePresence(show, EXIT_MS)
  const [growing, setGrowing] = useState(false)
  const [wasShown, setWasShown] = useState(show)
  const kept = useRef(children)
  if (show) kept.current = children
  if (show !== wasShown) {
    setWasShown(show)
    setGrowing(show)
  }
  if (!shown) return null
  const motion = show ? (growing ? ' rvin' : '') : ' rvout'
  return (
    <div
      className={'rv' + motion}
      inert={!show}
      onAnimationEnd={(e) => {
        if (e.target === e.currentTarget && show) setGrowing(false)
      }}
    >
      <div className="rvb">{kept.current}</div>
    </div>
  )
}
