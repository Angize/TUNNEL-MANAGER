import { useId, useState } from 'react'
import Reveal from '../../components/Reveal.jsx'
import Chevron from '../../components/Chevron.jsx'

export function byName(a, b) {
  return String(a.name).localeCompare(String(b.name), 'en', { numeric: true })
}

function Group({ group, open, onToggle }) {
  const bodyId = useId()
  return (
    <div className={'og ' + group.tone + (open ? ' open' : '')}>
      <button type="button" className="sgh" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>
        <i className="dot" />
        <b>{group.title}</b>
        {group.hint ? <small className="ogt">{group.hint}</small> : null}
        <em>{group.items.length}</em>
        <Chevron className="sgc" />
      </button>
      {!open && group.preview ? <div className="sgp">{group.preview}</div> : null}
      <Reveal show={open}>
        <div className="ogb" id={bodyId}>
          {group.items.map(group.row)}
        </div>
      </Reveal>
    </div>
  )
}

export default function StatusGroups({ groups }) {
  const [picked, setPicked] = useState({})
  const isOpen = (g) => (g.key in picked ? picked[g.key] : !!g.open)

  return (
    <div className="sgrp">
      {groups
        .filter((g) => g.items.length)
        .map((g) => (
          <Group key={g.key} group={g} open={isOpen(g)} onToggle={() => setPicked((cur) => ({ ...cur, [g.key]: !isOpen(g) }))} />
        ))}
    </div>
  )
}
