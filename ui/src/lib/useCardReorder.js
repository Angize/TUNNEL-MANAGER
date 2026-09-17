import { useCallback, useEffect, useRef, useState } from 'react'
import { flushSync } from 'react-dom'
import { apiPost, NET_TIMEOUT } from './api.js'
import { postError } from './errors.js'
import { closeCard } from './openCards.js'
import { listBusy, reorderMode, setDragging, setSaving } from './reorder.js'
import { toast } from './toast.js'

const EDGE = 76
const MAX_STEP = 24

function capturePointer(node, id) {
  try {
    node.setPointerCapture(id)
    return true
  } catch {
    return false
  }
}

function releasePointer(node, id) {
  try {
    node.releasePointerCapture(id)
    return true
  } catch {
    return false
  }
}

function buzz() {
  try {
    if (navigator.vibrate) navigator.vibrate(10)
    return true
  } catch {
    return false
  }
}

function swap(order, a, b) {
  const i = order.indexOf(a)
  const j = order.indexOf(b)
  if (i < 0 || j < 0) return order
  const next = order.slice()
  next[i] = b
  next[j] = a
  return next
}

function scrollStep(y, height) {
  if (y < EDGE) return -Math.min(MAX_STEP, (((EDGE - y) / 3) | 0) + 3)
  if (y > height - EDGE) return Math.min(MAX_STEP, (((y - (height - EDGE)) / 3) | 0) + 3)
  return 0
}

export default function useCardReorder(kind, ids, onSaved) {
  const [order, setOrder] = useState(ids)
  const drag = useRef(null)
  const orderRef = useRef(order)
  const savedRef = useRef(onSaved)
  const idsKey = useRef(ids.join(','))
  const idsRef = useRef(ids)

  orderRef.current = order
  savedRef.current = onSaved
  idsRef.current = ids

  const key = ids.join(',')
  if (idsKey.current !== key && !drag.current) {
    idsKey.current = key
    setOrder(ids.slice())
  }

  const apply = useCallback(() => {
    const d = drag.current
    if (!d) return

    const shift = (node) => {
      const otherId = node.getAttribute('data-rid')
      const cardTop = d.card.getBoundingClientRect().top
      const nodeTop = node.getBoundingClientRect().top

      flushSync(() => setOrder(swap(orderRef.current, d.id, otherId)))

      d.grabY += d.card.getBoundingClientRect().top - cardTop
      d.card.style.transform = 'translateY(' + (d.lastY - d.grabY) + 'px)'

      const dy = nodeTop - node.getBoundingClientRect().top
      if (dy) {
        node.style.transition = 'none'
        node.style.transform = 'translateY(' + dy + 'px)'
        void node.offsetHeight
        node.style.transition = ''
        node.style.transform = ''
      }
      d.swaps.push(otherId)
    }

    d.card.style.transform = 'translateY(' + (d.lastY - d.grabY) + 'px)'
    const rect = d.card.getBoundingClientRect()
    const middle = rect.top + rect.height / 2
    const sibling = (el) =>
      el && el.getAttribute && el.getAttribute('data-rid') && el.getAttribute('data-rk') === kind
        ? el
        : null

    const prev = sibling(d.card.previousElementSibling)
    if (prev) {
      const r = prev.getBoundingClientRect()
      if (middle < r.top + r.height / 2) {
        shift(prev)
        return
      }
    }
    const next = sibling(d.card.nextElementSibling)
    if (next) {
      const r = next.getBoundingClientRect()
      if (middle > r.top + r.height / 2) shift(next)
    }
  }, [kind])

  const autoScroll = useCallback(() => {
    const d = drag.current
    if (!d) return
    const height = window.innerHeight || document.documentElement.clientHeight
    let step = scrollStep(d.lastY, height)
    const at = window.pageYOffset
    if (step > 0) step = Math.min(step, d.maxY - at)
    else if (step < 0) step = Math.max(step, -at)
    if (step) {
      window.scrollBy(0, step)
      const moved = window.pageYOffset - at
      if (moved) {
        d.grabY -= moved
        apply()
      }
    }
    d.raf = requestAnimationFrame(autoScroll)
  }, [apply])

  const persist = useCallback(
    async (id, targets) => {
      setSaving(true)
      const r = await apiPost('reorder', { kind, id, targets }, NET_TIMEOUT)
      if (!(r.ok && r.d.ok)) {
        toast(postError(r, 'reorder_err'), 'err')
        setOrder(idsRef.current.slice())
      }
      setSaving(false)
      savedRef.current()
    },
    [kind]
  )

  useEffect(() => {
    const down = (e) => {
      if (drag.current || !reorderMode() || listBusy()) return
      if (e.isPrimary === false) return
      if (e.pointerType === 'mouse' && e.button !== 0) return
      const handle = e.target.closest ? e.target.closest('.rgrip') : null
      if (!handle) return
      const card = handle.closest('.card[data-rid]')
      if (!card || card.getAttribute('data-rk') !== kind) return
      if (e.cancelable) e.preventDefault()

      const id = card.getAttribute('data-rid')
      closeCard(id)
      const height = window.innerHeight || document.documentElement.clientHeight
      drag.current = {
        card,
        id,
        pid: e.pointerId,
        grabY: e.clientY,
        lastY: e.clientY,
        swaps: [],
        raf: 0,
        maxY: Math.max(0, (document.documentElement.scrollHeight || 0) - height),
      }
      capturePointer(card, e.pointerId)
      setDragging(id)
      buzz()
      drag.current.raf = requestAnimationFrame(autoScroll)
    }

    const move = (e) => {
      const d = drag.current
      if (!d) return
      if (e.cancelable) e.preventDefault()
      d.lastY = e.clientY
      apply()
    }

    const end = (e) => {
      const d = drag.current
      if (!d) return
      if (e && e.pointerId != null && e.pointerId !== d.pid) return
      drag.current = null
      if (d.raf) cancelAnimationFrame(d.raf)
      releasePointer(d.card, d.pid)
      d.card.style.transform = ''
      setDragging('')
      if (d.swaps.length) persist(d.id, d.swaps)
    }

    const lost = (e) => {
      const d = drag.current
      if (!d || e.pointerId !== d.pid) return
      capturePointer(d.card, e.pointerId)
    }

    const block = (e) => {
      if (drag.current && e.cancelable) e.preventDefault()
    }

    document.addEventListener('pointerdown', down, true)
    document.addEventListener('pointermove', move, true)
    document.addEventListener('pointerup', end, true)
    document.addEventListener('pointercancel', end, true)
    document.addEventListener('lostpointercapture', lost, true)
    document.addEventListener('touchmove', block, { passive: false })
    return () => {
      document.removeEventListener('pointerdown', down, true)
      document.removeEventListener('pointermove', move, true)
      document.removeEventListener('pointerup', end, true)
      document.removeEventListener('pointercancel', end, true)
      document.removeEventListener('lostpointercapture', lost, true)
      document.removeEventListener('touchmove', block)
      const d = drag.current
      if (!d) return
      drag.current = null
      if (d.raf) cancelAnimationFrame(d.raf)
      setDragging('')
    }
  }, [kind, apply, autoScroll, persist])

  return order
}
