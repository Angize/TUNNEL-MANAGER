import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import Icon from './Icon.jsx'
import { dismissToast, subscribeToasts } from '../lib/toast.js'

const GAP = 8
const PEEK = 9
const SHRINK = 0.05
const DEPTH = 3

function stack(root, open) {
  const list = [...root.children].filter((el) => !el.classList.contains('out')).reverse()
  let above = 0
  list.forEach((el, i) => {
    el.style.setProperty('--y', (open ? -above : -i * PEEK) + 'px')
    el.style.setProperty('--s', String(open ? 1 : 1 - i * SHRINK))
    el.style.zIndex = String(100 - i)
    el.classList.toggle('deep', !open && i >= DEPTH)
    above += el.offsetHeight + GAP
  })
  if (!list.length) return 0
  return open ? above - GAP : list[0].offsetHeight + PEEK * (Math.min(list.length, DEPTH) - 1)
}

function fitFoot(root, height) {
  if (!height) return
  root.style.bottom = ''
  const feet = document.querySelectorAll('.modalov:not(.leaving) .mfoot')
  const foot = feet[feet.length - 1]
  root.classList.toggle('fitted', !!foot)
  if (!foot) return
  const base = innerHeight - parseFloat(getComputedStyle(root).bottom)
  const r = foot.getBoundingClientRect()
  if (r.top >= base || r.bottom <= base - height) return
  root.style.bottom = innerHeight - r.top + GAP + 'px'
}

export default function ToastHost() {
  const [items, setItems] = useState([])
  const [open, setOpen] = useState(false)
  const box = useRef(null)

  useEffect(() => subscribeToasts(setItems), [])

  const live = items.filter((t) => !t.out).length
  if (open && live < 2) setOpen(false)

  useLayoutEffect(() => {
    fitFoot(box.current, stack(box.current, open))
  }, [items, open])

  return (
    <div ref={box} className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          data-id={t.id}
          className={'toast ' + t.kind + (t.show ? ' show' : '') + (t.out ? ' out' : '')}
          role={t.kind === 'err' ? 'alert' : undefined}
          onClick={() => {
            if (!open && live > 1) setOpen(true)
            else dismissToast(t.id)
          }}
        >
          {t.kind === 'ok' ? <Icon name="okc" /> : t.kind === 'err' ? <Icon name="xc" /> : null}
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
