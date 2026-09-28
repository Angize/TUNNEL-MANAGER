import { useLayoutEffect, useRef } from 'react'
import { gsap, reducedMotion } from './motion.js'
import { riseIn } from './riseIn.js'

const MOVE_S = 0.32
const ENTER_S = 0.3
const EXIT_S = 0.2
const SLIDE_S = 0.28
const HOLD_S = 0.18

function place(el) {
  return {
    x: el.offsetLeft + (Number(gsap.getProperty(el, 'x')) || 0),
    y: el.offsetTop + (Number(gsap.getProperty(el, 'y')) || 0),
  }
}

function bottomOf(els) {
  const last = els[els.length - 1]
  return last ? last.offsetTop + last.offsetHeight + parseFloat(getComputedStyle(last).marginBottom) : 0
}

function ghostOut(root, g, slide) {
  const ghost = g.el.cloneNode(true)
  ghost.removeAttribute('id')
  ghost.setAttribute('aria-hidden', 'true')
  ghost.inert = true
  ghost.classList.add('flghost')
  Object.assign(ghost.style, { top: g.y + 'px', left: g.x + 'px', width: g.w + 'px' })
  root.appendChild(ghost)
  const to = slide
    ? { xPercent: -110, opacity: 0, duration: SLIDE_S, ease: 'ease-in-out' }
    : { opacity: 0, scale: 0.97, duration: EXIT_S, ease: 'ease-out' }
  gsap.to(ghost, { ...to, onComplete: () => ghost.remove() })
}

export default function useFlipList(
  box,
  keys,
  context,
  { enter = true, exit = true, hold = false, slides = () => true } = {}
) {
  const last = useRef(null)
  const plan = useRef(null)
  const quiet = useRef(false)
  const entered = useRef(false)
  const sig = keys && !hold ? keys.join('\n') : null
  const prev = last.current

  if (box.current && prev && sig !== null && prev.sig !== sig && !plan.current) {
    if (prev.context === context && !quiet.current && !reducedMotion()) {
      const next = new Set(keys)
      const where = new Map([...prev.els.values()].map((el) => [el, place(el)]))
      plan.current = {
        where,
        height: box.current.offsetHeight,
        top: box.current.getBoundingClientRect().top,
        ghosts: exit
          ? [...prev.els]
              .filter(([key]) => !next.has(key))
              .map(([key, el]) => ({ el, slide: slides(key), ...where.get(el), w: el.offsetWidth }))
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
    if (!entered.current) {
      entered.current = true
      if (enter) riseIn([...els.values()])
    }
    if (!p) return
    const fresh = [...els.values()].filter((el) => !p.where.has(el))
    const slide = !fresh.length && p.ghosts.some((g) => g.slide)
    const shift = p.top - root.getBoundingClientRect().top
    const height = bottomOf([...els.values()])
    gsap.killTweensOf(root)
    if (p.height > height) {
      gsap.fromTo(root, { minHeight: p.height }, {
        minHeight: height,
        duration: MOVE_S,
        delay: slide ? HOLD_S : 0,
        ease: 'ease-out',
        clearProps: 'minHeight',
      })
    } else gsap.set(root, { clearProps: 'minHeight' })
    p.ghosts.forEach((g) => ghostOut(root, { ...g, y: g.y + shift }, slide && g.slide))
    for (const el of els.values()) {
      const was = p.where.get(el)
      if (!was) continue
      const dx = was.x - el.offsetLeft
      const dy = was.y - el.offsetTop + shift
      const moving = gsap.getTweensOf(el).filter((t) => 'y' in t.vars)
      if (!dx && !dy && !moving.length) continue
      moving.forEach((t) => t.kill())
      el.classList.add('flipping')
      gsap.fromTo(el, { x: dx, y: dy }, {
        x: 0,
        y: 0,
        duration: MOVE_S,
        delay: slide ? HOLD_S : 0,
        ease: 'ease-out',
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
