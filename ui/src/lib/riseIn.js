import { EASE_OUT, reducedMotion } from './motion.js'

const RISE_MS = 300
const RISE_STEP_MS = 40
const RISE_MAX = 10

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

export function riseIn(els) {
  if (reducedMotion()) return
  els
    .filter((el) => {
      const r = el.getBoundingClientRect()
      return r.bottom > 0 && r.top < innerHeight && !el.closest('[inert]')
    })
    .slice(0, RISE_MAX)
    .forEach((el, i) => {
      el.animate([{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], {
        duration: RISE_MS,
        delay: i * RISE_STEP_MS,
        easing: EASE_OUT,
        fill: 'backwards',
      })
    })
}
