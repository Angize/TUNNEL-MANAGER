const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

function focusables(root) {
  return [...root.querySelectorAll(FOCUSABLE)].filter((el) => el.getClientRects().length > 0)
}

export function trapTab(e, root) {
  if (e.key !== 'Tab' || !root) return
  const items = focusables(root)
  if (!items.length) {
    e.preventDefault()
    root.focus()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  const inside = root.contains(document.activeElement)
  if (e.shiftKey && (!inside || document.activeElement === first || document.activeElement === root)) {
    e.preventDefault()
    last.focus()
  } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
    e.preventDefault()
    first.focus()
  }
}

export function coarsePointer() {
  return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches)
}

export function restoreFocus(el) {
  if (el && typeof el.focus === 'function' && document.contains(el)) el.focus()
}
