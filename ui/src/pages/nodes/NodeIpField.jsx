import { useState } from 'react'
import Field from '../../components/Field.jsx'
import { T } from '../../i18n/fa.js'
import { IPV4, isIpv4 } from '../../lib/cdn.js'
import { LTR_TEXT } from '../../lib/form.js'
import { latinNumber } from '../../lib/num.js'

export default function NodeIpField({ value, onChange, inputRef, placeholder, first, error }) {
  const [checked, setChecked] = useState(false)
  return (
    <Field first={first} label={T('nadd_srv_ip')} error={error || (checked && !isIpv4(value.trim()) && T('node_ip_invalid'))}>
      <input
        {...LTR_TEXT}
        ref={inputRef}
        inputMode="decimal"
        required
        pattern={IPV4.source}
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(latinNumber(e.target.value))}
        onBlur={() => { setChecked(true); if (value !== value.trim()) onChange(value.trim()) }}
        onInvalid={e => { setChecked(true); e.currentTarget.focus() }}
      />
    </Field>
  )
}
