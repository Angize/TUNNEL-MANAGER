import { useLayoutEffect } from 'react'
import useFlipList from './useFlipList.js'

function stackColumns(root, cards) {
  if (!root.clientWidth) return
  const columns = getComputedStyle(root).gridTemplateColumns.split(' ').length
  if (columns === 1) {
    for (const card of cards) card.style.removeProperty('margin-block-start')
    return
  }
  const heights = cards.map((card) => {
    const style = getComputedStyle(card)
    return parseFloat(style.height) + parseFloat(style.marginBlockEnd)
  })
  const bottoms = Array(columns).fill(0)
  let rowTop = 0
  cards.forEach((card, index) => {
    const column = index % columns
    if (column === 0) rowTop = Math.max(...bottoms)
    card.style.marginBlockStart = (bottoms[column] - rowTop) + 'px'
    bottoms[column] += heights[index]
  })
}

export default function useCardList(box, keys, context, options) {
  const order = keys?.join('\n')
  useLayoutEffect(() => {
    if (!order) return
    const root = box.current
    const cards = [...root.children].filter((el) => el.matches('.card:not(.flghost)'))
    const layout = () => stackColumns(root, cards)
    layout()
    const observer = new ResizeObserver(layout)
    for (const card of cards) observer.observe(card, { box: 'border-box' })
    window.addEventListener('resize', layout)
    return () => {
      observer.disconnect()
      window.removeEventListener('resize', layout)
    }
  }, [box, order])
  useFlipList(box, keys, context, options)
}
