import { useLayoutEffect, useRef } from 'react'
import { EASE_OUT, reducedMotion } from './motion.js'

const MOVE_MS = 340
const OUT_MS = 160
const IN_MS = 260
const STAGGER_MS = 50
const SIZE = 'swapsize'
const WHOLE = 'button,input,textarea,select,label,a,svg,[role=switch],[role=radio],[role=checkbox]'
const SIDES = ['Top', 'Right', 'Bottom', 'Left']

function spot(el, at) {
  const r = el.getBoundingClientRect()
  return { x: r.left - at.left, y: r.top - at.top, w: r.width, h: r.height }
}

function clear(color) {
  return color === 'transparent' || /,\s*0\)$/.test(color)
}

function whole(el, s) {
  if (!el.children.length || el.matches(WHOLE)) return true
  if ([...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) return true
  if (s.backgroundImage !== 'none' || s.boxShadow !== 'none' || !clear(s.backgroundColor)) return true
  return SIDES.some((k) => parseFloat(s['border' + k + 'Width']) > 0 && !clear(s['border' + k + 'Color']))
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

function diff(body, spots) {
  const at = body.getBoundingClientRect()
  const rtl = getComputedStyle(body).direction === 'rtl'
  const moves = []
  const fresh = []
  const visit = (el, ax, ay) => {
    for (const c of el.children) {
      if (c.classList.contains('swghost')) continue
      const s = getComputedStyle(c)
      if (s.display === 'contents') {
        visit(c, ax, ay)
        continue
      }
      if (!c.getClientRects().length) continue
      const now = spot(c, at)
      const p = spots.get(c)
      if (!p || !p.w || !p.h) {
        if (!whole(c, s)) visit(c, ax, ay)
        else if (now.w && now.h && now.y < at.height && now.y + now.h > 0) fresh.push([c, now])
        continue
      }
      const dx = rtl ? p.x + p.w - now.x - now.w : p.x - now.x
      const dy = p.y - now.y
      if (Math.abs(dx - ax) > 0.5 || Math.abs(dy - ay) > 0.5) moves.push([c, dx - ax, dy - ay])
      if (!c.matches(WHOLE)) visit(c, dx, dy)
    }
  }
  visit(body, 0, 0)
  return { moves, fresh }
}

export default function useSwapFlip(root, key) {
  const last = useRef(key)
  const plan = useRef(null)
  const swapping =
    !!(root && root.current) && last.current != null && key != null && last.current !== key && !reducedMotion()

  if (swapping && !plan.current) {
    const body = root.current
    const at = body.getBoundingClientRect()
    plan.current = {
      spots: new Map([...body.querySelectorAll('*')].map((el) => [el, spot(el, at)])),
      height: body.closest('.modal').offsetHeight,
    }
  }

  useLayoutEffect(() => {
    last.current = key
    const was = plan.current
    plan.current = null
    const body = root && root.current
    if (!was || !body) return
    const box = body.closest('.modal')
    for (const a of [...box.getAnimations(), ...body.getAnimations()]) {
      if (a.id === SIZE) a.cancel()
    }
    for (const el of body.querySelectorAll('.rvin, .rvin > .rvb, .rvout')) {
      for (const a of el.getAnimations()) a.finish()
    }
    const { moves, fresh } = diff(body, was.spots)
    resize(body, box, was.height)
    was.spots.forEach((p, el) => {
      if (!el.parentNode && p.w && p.h) ghostOut(body, el, p)
    })
    for (const [el, dx, dy] of moves) {
      el.animate([{ translate: dx + 'px ' + dy + 'px' }, { translate: '0 0' }], {
        duration: MOVE_MS,
        easing: EASE_OUT,
      })
    }
    fresh.sort((a, b) => a[1].y - b[1].y)
    let step = -1
    let line = -Infinity
    for (const [el, now] of fresh) {
      if (now.y >= line) {
        step++
        line = now.y + now.h
      }
      el.animate([{ opacity: 0, translate: '0 10px' }, { opacity: 1, translate: '0 0' }], {
        duration: IN_MS,
        delay: 80 + STAGGER_MS * step,
        easing: EASE_OUT,
        fill: 'backwards',
      })
    }
  }, [root, key])

  return swapping
}
