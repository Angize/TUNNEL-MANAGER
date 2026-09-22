import { useCallback, useEffect, useLayoutEffect, useRef } from 'react'
import PageHead from './PageHead.jsx'
import { T } from '../i18n/fa.js'
import { num } from '../lib/num.js'
import { useSummary } from '../state/SummaryContext.jsx'
import './tabpager.css'

const SETTLE_MS = 120
const HAS_SCROLLEND = typeof window !== 'undefined' && 'onscrollend' in window

function reducedMotion() {
  return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)
}

function pageTop(el) {
  let top = 0
  for (let node = el; node; node = node.offsetParent) top += node.offsetTop
  return top
}

export default function TabPager({ icon, titleKey, kinds, kind, onKind, onNavigate }) {
  const { counts } = useSummary()
  const index = Math.max(0, kinds.findIndex((k) => k.id === kind))
  const pager = useRef(null)
  const seg = useRef(null)
  const thumb = useRef(null)
  const dots = useRef(null)
  const sub = useRef(null)
  const panes = useRef([])
  const placed = useRef(false)
  const sized = useRef(false)
  const settle = useRef(0)
  const touching = useRef(false)
  const indexRef = useRef(index)

  indexRef.current = index

  const paint = useCallback((f) => {
    const box = seg.current
    const bar = thumb.current
    if (!box || !bar) return
    const buttons = box.querySelectorAll('button')
    const lo = Math.floor(f)
    const hi = Math.min(kinds.length - 1, lo + 1)
    const t = f - lo
    const a = buttons[lo]
    const b = buttons[hi]
    if (!a || !b) return
    bar.style.left = a.offsetLeft + (b.offsetLeft - a.offsetLeft) * t + 'px'
    bar.style.width = a.offsetWidth + (b.offsetWidth - a.offsetWidth) * t + 'px'
    const near = Math.round(f)
    buttons.forEach((el, i) => el.classList.toggle('on', i === near))
    if (dots.current) {
      dots.current.querySelectorAll('i').forEach((el, i) => el.classList.toggle('on', i === near))
    }
  }, [kinds])

  const position = useCallback(() => {
    const el = pager.current
    if (!el || !el.clientWidth) return 0
    return Math.min(kinds.length - 1, Math.max(0, Math.abs(el.scrollLeft) / el.clientWidth))
  }, [kinds])

  const target = useCallback((i) => {
    const el = pager.current
    const rtl = getComputedStyle(el).direction === 'rtl'
    return (rtl ? -1 : 1) * i * el.clientWidth
  }, [])

  const fit = useCallback((glide) => {
    const el = pager.current
    const pane = panes.current[indexRef.current]
    if (!el || !pane) return
    const next = Math.max(pane.offsetHeight, Math.floor(window.innerHeight - pageTop(el))) + 'px'
    if (el.style.height === next) return
    el.classList.toggle('glide', glide === true)
    el.style.height = next
  }, [])

  useEffect(() => {
    const el = pager.current
    if (!el) return undefined
    const passive = { passive: true }
    const commit = () => {
      const near = Math.round(position())
      if (near !== indexRef.current && kinds[near]) onKind(kinds[near].id)
    }
    const later = () => {
      clearTimeout(settle.current)
      settle.current = setTimeout(() => {
        if (!touching.current) commit()
      }, SETTLE_MS)
    }
    const scroll = () => {
      paint(position())
      if (!HAS_SCROLLEND) later()
    }
    const down = () => {
      touching.current = true
    }
    const up = (e) => {
      if (e.touches.length) return
      touching.current = false
      later()
    }
    el.addEventListener('scroll', scroll, passive)
    if (HAS_SCROLLEND) {
      el.addEventListener('scrollend', commit, passive)
    } else {
      el.addEventListener('touchstart', down, passive)
      el.addEventListener('touchend', up, passive)
      el.addEventListener('touchcancel', up, passive)
    }
    return () => {
      clearTimeout(settle.current)
      el.removeEventListener('scroll', scroll, passive)
      el.removeEventListener('scrollend', commit, passive)
      el.removeEventListener('touchstart', down, passive)
      el.removeEventListener('touchend', up, passive)
      el.removeEventListener('touchcancel', up, passive)
    }
  }, [kinds, onKind, paint, position])

  useLayoutEffect(() => {
    const el = pager.current
    if (!el) return
    const goal = target(index)
    if (Math.abs(el.scrollLeft - goal) < 2) {
      paint(index)
    } else if (!placed.current || reducedMotion()) {
      el.scrollLeft = goal
      paint(index)
    } else {
      el.scrollTo({ left: goal, behavior: 'smooth' })
    }
    placed.current = true
  }, [index, paint, target])

  useLayoutEffect(() => {
    fit(sized.current)
    sized.current = true
    const pane = panes.current[index]
    if (!pane || typeof ResizeObserver === 'undefined') return undefined
    const observer = new ResizeObserver(() => fit(false))
    observer.observe(pane)
    if (sub.current) observer.observe(sub.current)
    return () => observer.disconnect()
  }, [index, fit])

  useEffect(() => {
    const onResize = () => {
      const el = pager.current
      if (!el) return
      el.scrollLeft = target(indexRef.current)
      paint(position())
      fit()
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [fit, paint, position, target])

  return (
    <>
      <PageHead icon={icon} titleKey={titleKey} />

      <div className="lseg" ref={seg}>
        <span className="lthumb" ref={thumb} />
        {kinds.map((k, i) => (
          <button
            key={k.id}
            type="button"
            className={i === index ? 'on' : ''}
            aria-pressed={i === index}
            onClick={() => onKind(k.id)}
          >
            {T(k.labelKey)}
            <i>{num(counts[k.count])}</i>
          </button>
        ))}
      </div>

      <div className="ldots" ref={dots} aria-hidden="true">
        {kinds.map((k, i) => (
          <i key={k.id} className={i === index ? 'on' : ''} />
        ))}
      </div>

      <p className="sub lsub" ref={sub}>
        {T(kinds[index].subKey)}
      </p>

      <div className="lpager" ref={pager}>
        {kinds.map((k, i) => (
          <section
            key={k.id}
            className="lpane"
            ref={(el) => {
              panes.current[i] = el
            }}
            inert={i !== index}
          >
            <k.Page active={i === index} onNavigate={onNavigate} />
          </section>
        ))}
      </div>
    </>
  )
}
