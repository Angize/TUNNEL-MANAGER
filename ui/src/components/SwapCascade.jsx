import { useContext } from 'react'
import useSwapFlip from '../lib/useSwapFlip.js'
import { RevealSwap, SwapRoot } from '../lib/revealSwap.js'

export default function SwapCascade({ value, children }) {
  const swapping = useSwapFlip(useContext(SwapRoot), value)
  return <RevealSwap value={swapping}>{children}</RevealSwap>
}
