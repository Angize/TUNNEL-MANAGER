import { useLayoutEffect, useRef } from 'react'
import { EASE_OUT, reducedMotion } from './motion.js'
import { formRows } from './formRows.js'

const MOVE_MS = 340
const OUT_MS = 160
const IN_MS = 260
const STAGGER_MS = 50
const SIZE = 'swapsize'

function spot(el, at) {
  const r = el.getBoundingClientRect()
  return { x: r.left - at.left, y: r.top - at.top, w: r.width }
}

function ghostOut(body, el, p) {
  el.classList.add('swghost')
  el.setAttribute('aria-hidden', 'true')
  el.inert = true
  Object.assign(el.style, {
    top: p.y - body.clientTop + body.scrollTop + 'px',
    left: p.x - body.clientLeft + body.scrollLeft + 'px',
    width: p.w + 'px',
  })
  body.appendChild(el)
  el.animate([{ opacity: 1 }, { opacity: 0, scale: '.98' }], {
    duration: OUT_MS,
    easing: EASE_OUT,
    fill: 'forwards',
  }).onfinish = () => el.remove()
}

function resize(body, box, was) {
  const now = box.offsetHeight
  if (Math.abs(now - was) < 1) return
  const bar = body.scrollHeight > body.clientHeight ? 'scroll' : 'hidden'
  box.animate([{ height: was + 'px' }, { height: now + 'px' }], { id: SIZE, duration: MOVE_MS, easing: EASE_OUT })
  body.animate([{ overflowY: bar }, { overflowY: bar }], { id: SIZE, duration: MOVE_MS })
}

function rowsOf(body, zone, wraps) {
  const out = []
  const around = (rows) => {
    for (const el of rows) {
      if (zone.contains(el)) continue
      if (!el.contains(zone)) out.push(el)
      else {
        if (wraps) wraps.push(el)
        around(formRows(el, wraps))
      }
    }
  }
  around(formRows(body, wraps))
  return out.concat(formRows(zone, wraps))
}

export default function useSwapFlip(root, zone, key) {
  const last = useRef(key)
  const plan = useRef(null)
  const swapping =
    !!(root && root.current) && last.current != null && key != null && last.current !== key && !reducedMotion()

  if (swapping && !plan.current && zone.current) {
    const body = root.current
    const at = body.getBoundingClientRect()
    const wraps = []
    const rows = rowsOf(body, zone.current, wraps)
    plan.current = {
      spots: new Map([...wraps, ...rows].map((el) => [el, spot(el, at)])),
      height: body.closest('.modal').offsetHeight,
    }
  }

  useLayoutEffect(() => {
    last.current = key
    const was = plan.current
    plan.current = null
    const body = root && root.current
    if (!was || !body || !zone.current) return
    const box = body.closest('.modal')
    for (const a of [...box.getAnimations(), ...body.getAnimations()]) {
      if (a.id === SIZE) a.cancel()
    }
    for (const el of body.querySelectorAll('.rvin, .rvin > .rvb, .rvout')) {
      for (const a of el.getAnimations()) a.finish()
    }
    const at = body.getBoundingClientRect()
    const rows = rowsOf(body, zone.current).map((el) => [el, spot(el, at)])
    resize(body, box, was.height)
    was.spots.forEach((p, el) => {
      if (!el.parentNode) ghostOut(body, el, p)
    })
    const rtl = getComputedStyle(body).direction === 'rtl'
    let fresh = 0
    for (const [el, now] of rows) {
      const p = was.spots.get(el)
      if (!p) {
        if (now.y >= at.height) continue
        el.animate([{ opacity: 0, translate: '0 10px' }, { opacity: 1, translate: '0 0' }], {
          duration: IN_MS,
          delay: 80 + STAGGER_MS * fresh++,
          easing: EASE_OUT,
          fill: 'backwards',
        })
        continue
      }
      const dx = rtl ? p.x + p.w - now.x - now.w : p.x - now.x
      const dy = p.y - now.y
      if (dx || dy) {
        el.animate([{ translate: dx + 'px ' + dy + 'px' }, { translate: '0 0' }], {
          duration: MOVE_MS,
          easing: EASE_OUT,
        })
      }
    }
  }, [root, zone, key])

  return swapping
}
