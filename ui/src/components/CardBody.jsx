import { useState } from 'react'

export default function CardBody({ open, children }) {
  const [opened, setOpened] = useState(open)
  if (open && !opened) setOpened(true)
  return (
    <div className="cbody" inert={!open}>
      <div className="cbody-in">{opened ? children : null}</div>
    </div>
  )
}
