import { useContext, useRef } from 'react'
import useSwapFlip from '../lib/useSwapFlip.js'
import { RevealSwap, SwapRoot } from '../lib/revealSwap.js'

export default function SwapCascade({ value, children }) {
  const zone = useRef(null)
  const swapping = useSwapFlip(useContext(SwapRoot), zone, value)
  return (
    <div className="swz" ref={zone}>
      <RevealSwap value={swapping}>{children}</RevealSwap>
    </div>
  )
}
