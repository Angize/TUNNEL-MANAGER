const WRAPS = ['ctabp', 'rv', 'rvb', 'swz']

export function formRows(root, wraps) {
  const out = []
  const walk = (el, depth) => {
    for (const c of el.children) {
      if (c.classList.contains('swghost')) continue
      if (c.classList.contains('ctabp') && !c.classList.contains('on')) continue
      if (depth < 5 && (WRAPS.some((k) => c.classList.contains(k)) || (!c.className && c.children.length > 1))) {
        if (wraps) wraps.push(c)
        walk(c, c.classList.contains('swz') ? depth : depth + 1)
      } else out.push(c)
    }
  }
  walk(root, 0)
  return out
}
