import { useId, useState } from 'react'
import { checkable } from '../lib/keys.js'

export default function SwitchRow({ on, title, note, locked, onToggle }) {
  const id = useId()
  const [flips, setFlips] = useState(0)
  const [was, setWas] = useState(on)
  if (on !== was) {
    setWas(on)
    setFlips(flips + 1)
  }
  return (
    <div
      className={'swrow' + (locked ? ' dis' : '') + (flips ? (flips % 2 ? ' flipa' : ' flipb') : '')}
      {...checkable('switch', on, onToggle, locked)}
      aria-labelledby={id + 't'}
      aria-describedby={note ? id + 'd' : undefined}
    >
      <span className="swtx">
        <b id={id + 't'}>{title}</b>
        {note ? <small id={id + 'd'}>{note}</small> : null}
      </span>
      <span className={'tglsw' + (on ? ' on' : '')} aria-hidden="true" />
    </div>
  )
}
