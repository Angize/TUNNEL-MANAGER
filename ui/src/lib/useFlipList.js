import { useLayoutEffect, useRef } from 'react'
import { gsap, reducedMotion } from './motion.js'

const MOVE_S = 0.32
const ENTER_S = 0.3
const EXIT_S = 0.2

function place(el) {
  return {
    x: el.offsetLeft + (Number(gsap.getProperty(el, 'x')) || 0),
    y: el.offsetTop + (Number(gsap.getProperty(el, 'y')) || 0),
  }
}

function ghostOut(root, g) {
  const ghost = g.el.cloneNode(true)
  ghost.removeAttribute('id')
  ghost.setAttribute('aria-hidden', 'true')
  ghost.inert = true
  ghost.classList.add('flghost')
  Object.assign(ghost.style, { top: g.y + 'px', left: g.x + 'px', width: g.w + 'px' })
  root.appendChild(ghost)
  gsap.to(ghost, { opacity: 0, scale: 0.97, duration: EXIT_S, ease: 'ease-out', onComplete: () => ghost.remove() })
}

export default function useFlipList(box, keys, context, { enter = true, exit = true, hold = false } = {}) {
  const last = useRef(null)
  const plan = useRef(null)
  const quiet = useRef(false)
  const sig = keys && !hold ? keys.join('\n') : null
  const prev = last.current

  if (box.current && prev && sig !== null && prev.sig !== sig && !plan.current) {
    if (prev.context === context && !quiet.current && !reducedMotion()) {
      const next = new Set(keys)
      const where = new Map([...prev.els.values()].map((el) => [el, place(el)]))
      plan.current = {
        where,
        ghosts: exit
          ? [...prev.els]
              .filter(([key]) => !next.has(key))
              .map(([, el]) => ({ el, ...where.get(el), w: el.offsetWidth }))
          : [],
      }
    }
  }

  useLayoutEffect(() => {
    const root = box.current
    const p = plan.current
    plan.current = null
    quiet.current = false
    if (!root || sig === null) {
      last.current = null
      return
    }
    const kids = [...root.children]
    const els = new Map(keys.map((key, i) => [key, kids[i]]).filter(([, el]) => el))
    last.current = { sig, context, els }
    if (!p) return
    p.ghosts.forEach((g) => ghostOut(root, g))
    const fresh = []
    for (const el of els.values()) {
      const was = p.where.get(el)
      if (!was) {
        fresh.push(el)
        continue
      }
      const dx = was.x - el.offsetLeft
      const dy = was.y - el.offsetTop
      if (!dx && !dy) continue
      el.classList.add('flipping')
      gsap.fromTo(el, { x: dx, y: dy }, {
        x: 0,
        y: 0,
        duration: MOVE_S,
        ease: 'ease-out',
        overwrite: 'auto',
        clearProps: 'transform',
        onComplete: () => el.classList.remove('flipping'),
      })
    }
    if (enter && fresh.length) {
      fresh.forEach((el) => el.classList.add('flipping'))
      gsap.fromTo(fresh, { opacity: 0, scale: 0.97 }, {
        opacity: 1,
        scale: 1,
        duration: ENTER_S,
        ease: 'ease-out',
        delay: p.ghosts.length ? 0.06 : 0,
        clearProps: 'opacity,transform',
        onComplete: () => fresh.forEach((el) => el.classList.remove('flipping')),
      })
    }
  })

  return () => {
    quiet.current = true
  }
}
