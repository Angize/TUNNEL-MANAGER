const LEAVE_MS = 280

export function leaveGhost(node) {
  if (!node || !node.isConnected) return
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return
  const ghost = node.cloneNode(true)
  const scrolls = [...node.querySelectorAll('*')].map((el) => el.scrollTop)
  queueMicrotask(() => {
    if (node.isConnected) return
    ghost.classList.add('leaving')
    ghost.setAttribute('aria-hidden', 'true')
    ghost.inert = true
    document.body.appendChild(ghost)
    ghost.querySelectorAll('*').forEach((el, i) => {
      if (scrolls[i]) el.scrollTop = scrolls[i]
    })
    setTimeout(() => ghost.remove(), LEAVE_MS)
  })
}
