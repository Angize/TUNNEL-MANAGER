import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import Icon from './Icon.jsx'
import { dismissToast, subscribeToasts } from '../lib/toast.js'
import { EASE_OUT, reducedMotion } from '../lib/motion.js'

function lift(el) {
  const now = getComputedStyle(el).translate
  const y = now && now !== 'none' ? parseFloat(now.split(' ')[1] || '0') || 0 : 0
  el.getAnimations().forEach((a) => {
    if (a.id === 'tlift') a.cancel()
  })
  return y
}

export default function ToastHost() {
  const [items, setItems] = useState([])
  const box = useRef(null)
  const seen = useRef(new Map())

  useEffect(() => subscribeToasts(setItems), [])

  useLayoutEffect(() => {
    const root = box.current
    const was = seen.current
    const now = new Map()
    for (const el of root.children) now.set(el.dataset.id, root.offsetHeight - el.offsetTop)
    seen.current = now
    if (reducedMotion()) return
    for (const el of root.children) {
      const before = was.get(el.dataset.id)
      if (before === undefined) continue
      const dy = now.get(el.dataset.id) - before + lift(el)
      if (Math.abs(dy) < 1) continue
      const a = el.animate([{ translate: '0 ' + dy + 'px' }, { translate: '0 0' }], { duration: 300, easing: EASE_OUT })
      a.id = 'tlift'
    }
  }, [items])

  return (
    <div ref={box} className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          data-id={t.id}
          className={'toast ' + t.kind + (t.show ? ' show' : '')}
          role={t.kind === 'err' ? 'alert' : undefined}
          onClick={() => dismissToast(t.id)}
        >
          {t.kind === 'ok' ? <Icon name="okc" /> : t.kind === 'err' ? <Icon name="xc" /> : null}
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
