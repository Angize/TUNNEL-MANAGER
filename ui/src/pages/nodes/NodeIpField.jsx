import { useState } from 'react'
import Field from '../../components/Field.jsx'
import { T } from '../../i18n/fa.js'
import { IPV4, isIpv4 } from '../../lib/cdn.js'
import { LTR_TEXT } from '../../lib/form.js'
import { latinNumber } from '../../lib/num.js'

export default function NodeIpField({ value, onChange, inputRef, placeholder, first, error }) {
  const [checked, setChecked] = useState(false)
  const change = (event) => {
    const input = event.currentTarget
    const raw = input.value
    const normalized = latinNumber(raw).trim()
    if (raw !== normalized) {
      const offset = raw.length - raw.trimStart().length
      const start = Math.max(0, input.selectionStart - offset)
      const end = Math.max(0, input.selectionEnd - offset)
      const direction = input.selectionDirection
      input.value = normalized
      input.setSelectionRange(start, end, direction)
    }
    onChange(normalized)
  }
  return (
    <Field first={first} label={T('nadd_srv_ip')} error={error || (checked && !isIpv4(value) && T('node_ip_invalid'))}>
      <input
        {...LTR_TEXT}
        ref={inputRef}
        inputMode="decimal"
        required
        pattern={IPV4.source}
        placeholder={placeholder}
        value={value}
        onChange={change}
        onBlur={() => setChecked(true)}
        onInvalid={e => { setChecked(true); e.currentTarget.focus() }}
      />
    </Field>
  )
}
