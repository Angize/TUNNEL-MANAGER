import { useState } from 'react'
import RichText from '../../components/RichText.jsx'
import { T } from '../../i18n/fa.js'

export default function SettingRow({ label, helpKey, exampleKey, children }) {
  const [open, setOpen] = useState(false)

  return (
    <div className={'sr' + (open ? ' exp-open' : '')}>
      <div className="srtop">
        <b className="srlbl">{label}</b>
        <button
          type="button"
          className="srq"
          aria-expanded={open ? 'true' : 'false'}
          onClick={() => setOpen(!open)}
        >
          {open ? '×' : '؟'}
        </button>
        <div className="srctl">{children}</div>
      </div>
      <div className="srexp">
        <p>
          <RichText text={T(helpKey)} />
        </p>
        <p className="srex">
          <RichText text={T(exampleKey)} />
        </p>
      </div>
    </div>
  )
}
