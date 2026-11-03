import { useEffect, useState } from 'react'
import Grip from './Grip.jsx'
import CardBody from './CardBody.jsx'
import Chevron from './Chevron.jsx'
import { isCardOpen, subscribeOpenCards, toggleCard } from '../lib/openCards.js'
import useDragging from '../lib/useDragging.js'
import { pressable } from '../lib/keys.js'

export default function AccordionCard({ id, kind, className, head, beforeBody, children }) {
  const [open, setOpen] = useState(() => isCardOpen(id))
  const dragging = useDragging(id)

  useEffect(() => subscribeOpenCards(() => setOpen(isCardOpen(id))), [id])

  return (
    <div
      className={
        'card ' + (className || '') + (open ? ' open' : '') + (dragging ? ' rdrag' : '')
      }
      data-rid={id}
      data-rk={kind}
    >
      <div className="chead" aria-expanded={open} {...pressable(() => toggleCard(id))}>
        {kind ? <Grip /> : null}
        {head}
        <Chevron />
      </div>
      {beforeBody}
      <CardBody open={open}>{children}</CardBody>
    </div>
  )
}
