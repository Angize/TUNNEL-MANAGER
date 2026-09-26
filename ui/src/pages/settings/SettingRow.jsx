import { cloneElement, useId, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import HelpPop from '../../components/HelpPop.jsx'
import usePresence from '../../lib/usePresence.js'
import { T, TF } from '../../i18n/fa.js'

const POP_EXIT_MS = 140

export default function SettingRow({ label, helpKey, exampleKey, unit, error, wide, half, children }) {
  const [open, setOpen] = useState(false)
  const shown = usePresence(open, POP_EXIT_MS)
  const help = useRef(null)
  const id = useId()
  const popId = id + 'h'
  const errorId = id + 'e'

  const close = (refocus) => {
    setOpen(false)
    if (refocus && help.current) help.current.focus()
  }

  return (
    <div className={'sr' + (wide ? ' wide' : '') + (half ? ' half' : '') + (error ? ' fld bad' : '')}>
      <div className="srtop">
        <label className="srlbl" htmlFor={id}>
          {label}
        </label>
        <button
          ref={help}
          type="button"
          className="srq"
          aria-haspopup="dialog"
          aria-expanded={open ? 'true' : 'false'}
          aria-controls={open ? popId : undefined}
          aria-label={TF('set_help_for', { f: label })}
          onClick={() => setOpen(!open)}
        >
          ؟
        </button>
        <div className={'srctl' + (unit ? ' unit' : '')}>
          {cloneElement(children, {
            id,
            'aria-describedby': error ? errorId : undefined,
            'aria-invalid': error ? 'true' : undefined,
          })}
          {unit ? <span className="srunit">{unit}</span> : null}
        </div>
      </div>
      {error ? (
        <div id={errorId} className="flderr" role="alert">
          <Icon name="warn" />
          <span>{error}</span>
        </div>
      ) : null}
      {shown ? (
        <HelpPop
          id={popId}
          anchor={help}
          title={label}
          text={T(helpKey)}
          example={T(exampleKey)}
          leaving={!open}
          onClose={close}
        />
      ) : null}
    </div>
  )
}
