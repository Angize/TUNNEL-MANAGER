import { useId, useState } from 'react'
import Reveal from '../../components/Reveal.jsx'

function Chevron() {
  return (
    <svg className="sgc" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 9l6 6 6-6" />
    </svg>
  )
}

function Group({ group, open, onToggle }) {
  const bodyId = useId()
  return (
    <div className={'sg ' + group.tone + (open ? ' open' : '')}>
      <button type="button" className="sgh" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>
        <i className="dot" />
        <b>{group.title}</b>
        {group.hint ? <small className="sgt">{group.hint}</small> : null}
        <em>{group.items.length}</em>
        <Chevron />
      </button>
      {!open && group.preview ? <div className="sgp">{group.preview}</div> : null}
      <Reveal show={open}>
        <div className="sgb" id={bodyId}>
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
