import { useEffect, useState } from 'react'
import { isCardOpen, subscribeOpenCards, toggleCard } from '../lib/openCards.js'

function Chevron() {
  return (
    <svg
      className="chev"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  )
}

export default function AccordionCard({ id, className, head, beforeBody, children }) {
  const [open, setOpen] = useState(() => isCardOpen(id))

  useEffect(() => subscribeOpenCards(() => setOpen(isCardOpen(id))), [id])

  return (
    <div
      className={'card ' + (className || '') + (open ? ' open' : '')}
      id={'c_' + id}
      data-rid={id}
    >
      <div className="chead" onClick={() => toggleCard(id)}>
        {head}
        <Chevron />
      </div>
      {beforeBody}
      <div className="cbody">
        <div className="cbody-in">{children}</div>
      </div>
    </div>
  )
}
