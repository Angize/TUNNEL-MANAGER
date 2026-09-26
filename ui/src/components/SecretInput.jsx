import { useState } from 'react'
import { LTR_TEXT } from '../lib/form.js'
import { T } from '../i18n/fa.js'

export default function SecretInput({ value, onChange, ...rest }) {
  const [shown, setShown] = useState(false)
  return (
    <div className="secret">
      <input
        {...rest}
        {...LTR_TEXT}
        className="phrtl"
        type={shown ? 'text' : 'password'}
        autoComplete="new-password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="button"
        className="secbtn"
        aria-pressed={shown ? 'true' : 'false'}
        onClick={() => setShown(!shown)}
      >
        {T('sec_show')}
      </button>
    </div>
  )
}
