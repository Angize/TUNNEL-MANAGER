import { latinNumber } from '../lib/num.js'

const KEEP = {
  int: /[^0-9]/g,
  decimal: /[^0-9.]/g,
  list: /[^0-9,،\s]/g,
}

const MODE = { int: 'numeric', decimal: 'decimal', list: 'numeric' }

export function cleanNumber(raw, kind) {
  return latinNumber(raw).replace(KEEP[kind || 'int'], '')
}

export default function NumberInput({ value, onChange, kind, ...rest }) {
  const k = kind || 'int'
  return (
    <input
      inputMode={MODE[k]}
      autoComplete="off"
      autoCorrect="off"
      spellCheck={false}
      {...rest}
      value={value == null ? '' : value}
      onChange={(e) => onChange(cleanNumber(e.target.value, k))}
    />
  )
}
