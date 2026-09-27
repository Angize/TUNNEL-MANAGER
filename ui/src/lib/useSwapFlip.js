import { useLayoutEffect, useRef } from 'react'
import { EASE_OUT, reducedMotion } from './motion.js'
import { formRows } from './formRows.js'

const MOVE_MS = 340
const OUT_MS = 160
const IN_MS = 260
const STAGGER_MS = 50

function spot(el, at) {
  const r = el.getBoundingClientRect()
  return { x: r.left - at.left, y: r.top - at.top, w: r.width }
}

function ghostOut(root, el, p) {
  el.classList.add('swghost')
  el.setAttribute('aria-hidden', 'true')
  el.inert = true
  Object.assign(el.style, { top: p.y + 'px', left: p.x + 'px', width: p.w + 'px' })
  root.appendChild(el)
  el.animate([{ opacity: 1 }, { opacity: 0, transform: 'scale(.98)' }], {
    duration: OUT_MS,
    easing: EASE_OUT,
    fill: 'forwards',
  }).onfinish = () => el.remove()
}

export default function useSwapFlip(box, key) {
  const last = useRef(key)
  const plan = useRef(null)
  const swapping = last.current != null && key != null && last.current !== key && !reducedMotion()

  if (swapping && !plan.current && box.current) {
    const at = box.current.getBoundingClientRect()
    const wraps = []
    const leaves = formRows(box.current, wraps)
    plan.current = new Map([...wraps, ...leaves].map((el) => [el, spot(el, at)]))
  }

  useLayoutEffect(() => {
    last.current = key
    const was = plan.current
    plan.current = null
    const root = box.current
    if (!was || !root) return
    was.forEach((p, el) => {
      if (!el.parentNode) ghostOut(root, el, p)
    })
    const at = root.getBoundingClientRect()
    const scroller = root.closest('.mbody')
    const bottom = scroller ? scroller.getBoundingClientRect().bottom : innerHeight
    let fresh = 0
    for (const el of formRows(root)) {
      const now = spot(el, at)
      const p = was.get(el)
      if (!p) {
        if (at.top + now.y >= bottom) continue
        el.animate([{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], {
          duration: IN_MS,
          delay: 80 + STAGGER_MS * fresh++,
          easing: EASE_OUT,
          fill: 'backwards',
        })
        continue
      }
      const dx = p.x - now.x
      const dy = p.y - now.y
      if (dx || dy) {
        el.animate([{ transform: 'translate(' + dx + 'px, ' + dy + 'px)' }, { transform: 'none' }], {
          duration: MOVE_MS,
          easing: EASE_OUT,
        })
      }
    }
  }, [box, key])

  return swapping
}
