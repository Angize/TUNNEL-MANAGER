import { useCallback, useEffect, useRef } from 'react'

const HOLD_MS = 450
const MOVE_TOLERANCE = 10

function buzz() {
  try {
    if (navigator.vibrate) navigator.vibrate(18)
  } catch {
    return
  }
}

function clearSelection() {
  try {
    const selection = window.getSelection()
    if (selection && selection.removeAllRanges) selection.removeAllRanges()
  } catch {
    return
  }
}

export default function useLongPress(onHold) {
  const timer = useRef(0)
  const origin = useRef({ x: 0, y: 0 })
  const onHoldRef = useRef(onHold)

  onHoldRef.current = onHold

  const cancel = useCallback(() => {
    clearTimeout(timer.current)
    timer.current = 0
  }, [])

  useEffect(() => cancel, [cancel])

  const start = useCallback(
    (event) => {
      if (event.touches && event.touches.length > 1) return
      if (event.target.closest('button,input,select,a,.act,.tsw,.tglsw,.modalov')) return
      const point = event.touches ? event.touches[0] : event
      origin.current = { x: point.clientX, y: point.clientY }
      clearTimeout(timer.current)
      timer.current = setTimeout(() => {
        timer.current = 0
        buzz()
        clearSelection()
        onHoldRef.current()
      }, HOLD_MS)
    },
    []
  )

  const move = useCallback(
    (event) => {
      if (!timer.current) return
      const point = event.touches ? event.touches[0] : event
      if (
        Math.abs(point.clientX - origin.current.x) > MOVE_TOLERANCE ||
        Math.abs(point.clientY - origin.current.y) > MOVE_TOLERANCE
      ) {
        cancel()
      }
    },
    [cancel]
  )

  return {
    onTouchStart: start,
    onTouchMove: move,
    onTouchEnd: cancel,
    onTouchCancel: cancel,
    onMouseDown: start,
    onMouseMove: move,
    onMouseUp: cancel,
    onMouseLeave: cancel,
    onContextMenu: (e) => e.preventDefault(),
  }
}
