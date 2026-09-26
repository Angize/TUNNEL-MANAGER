import { Children, cloneElement, isValidElement, useId } from 'react'
import Icon from './Icon.jsx'

export default function Field({ label, hint, error, first, className, style, children }) {
  const id = useId()
  const noteId = id + 'n'
  const note = error || hint
  let bound = false
  const kids = Children.map(children, (child) => {
    if (bound || !isValidElement(child)) return child
    bound = true
    return cloneElement(child, {
      id,
      'aria-describedby': note ? noteId : undefined,
      'aria-invalid': error ? 'true' : undefined,
    })
  })

  return (
    <div className={'fld' + (error ? ' bad' : '') + (className ? ' ' + className : '')} style={style}>
      {label ? (
        <label htmlFor={id} className={first ? 'first' : undefined}>
          {label}
        </label>
      ) : null}
      {kids}
      {error ? (
        <div id={noteId} className="flderr" role="alert">
          <Icon name="warn" />
          <span>{error}</span>
        </div>
      ) : hint ? (
        <div id={noteId} className="fldhint">
          {hint}
        </div>
      ) : null}
    </div>
  )
}
