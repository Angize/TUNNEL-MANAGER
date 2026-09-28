import { EASE_OUT, reducedMotion } from './motion.js'

const RISE_MS = 300
const RISE_STEP_MS = 40
const RISE_SPAN_MS = 360

export const CASCADE = [
  '.flist > .card',
  '.loglist > .lev',
  '.okpis > .card',
  '.osec > .card',
  '.ostat2 > .card',
  '.otiles > .otile',
  '.card.sg > .sgsec',
  '.stpage > .card:not(.sg)',
  '.upkeep > .card',
  '#agList > .nx',
].join(', ')

export function stepFor(count, step, span) {
  return count > 1 ? Math.min(step, span / (count - 1)) : step
}

export function onScreen(el) {
  const r = el.getBoundingClientRect()
  return r.bottom > 0 && r.top < innerHeight && !el.closest('[inert]')
}

export function riseIn(els) {
  if (reducedMotion()) return
  const shown = els.filter(onScreen)
  const step = stepFor(shown.length, RISE_STEP_MS, RISE_SPAN_MS)
  shown.forEach((el, i) => {
    el.animate([{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], {
      duration: RISE_MS,
      delay: i * step,
      easing: EASE_OUT,
      fill: 'backwards',
    })
  })
}
