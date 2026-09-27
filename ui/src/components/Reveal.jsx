import { useContext, useRef, useState } from 'react'
import usePresence from '../lib/usePresence.js'
import { RevealSwap } from '../lib/revealSwap.js'
import './reveal.css'

const EXIT_MS = 260

export default function Reveal({ show, instant, appear, children }) {
  const swap = useContext(RevealSwap)
  const shown = usePresence(show, EXIT_MS)
  const [growing, setGrowing] = useState(!!appear && show && !instant)
  const [wasShown, setWasShown] = useState(show)
  const [cut, setCut] = useState(false)
  const kept = useRef(children)
  if (show) kept.current = children
  if (show !== wasShown) {
    setWasShown(show)
    setGrowing(show && !instant && !swap)
    setCut(!show && swap)
  }
  if (!shown || (instant && !show) || cut) return null
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
