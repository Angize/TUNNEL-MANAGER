import { useState } from 'react'
import Icon from './Icon.jsx'
import NumberInput from './NumberInput.jsx'
import { T } from '../i18n/fa.js'
import { latinDigits } from '../lib/num.js'

const HAPTIC_MS = 15

function whole(text) {
  const s = latinDigits(text == null ? '' : String(text)).trim()
  return /^\d+$/.test(s) ? Number(s) : null
}

export default function Stepper({ value, onChange, min, max, step, unit, placeholder, ...rest }) {
  const by = step || 1
  const [bumps, setBumps] = useState(0)
  const [hits, setHits] = useState(0)
  const cur = whole(value) ?? whole(placeholder)
  const atMin = cur != null && cur <= min
  const atMax = cur != null && cur >= max
  const move = (dir) => {
    if (dir < 0 ? atMin : atMax) {
      setHits(hits + 1)
      if (navigator.vibrate) navigator.vibrate(HAPTIC_MS)
      return
    }
    const from = cur ?? min - dir * by
    const next = dir > 0 ? Math.floor(from / by) * by + by : Math.ceil(from / by) * by - by
    onChange(String(Math.min(max, Math.max(min, next))))
    setBumps(bumps + 1)
  }
  return (
    <div className={'stepper' + (hits ? (hits % 2 ? ' hita' : ' hitb') : '')}>
      <button
        type="button"
        className="stpb"
        aria-label={T('step_dec')}
        aria-disabled={atMin ? 'true' : undefined}
        onClick={() => move(-1)}
      >
        <Icon name="minus" />
      </button>
      <span className={'stpv' + (bumps ? (bumps % 2 ? ' bumpa' : ' bumpb') : '')}>
        <NumberInput
          {...rest}
          dir="ltr"
          placeholder={placeholder}
          value={value}
          style={unit ? { width: Math.max(1, String(value || placeholder || '').length) + 'ch' } : undefined}
          onChange={onChange}
        />
        {unit ? <span className="stpu">{unit}</span> : null}
      </span>
      <button
        type="button"
        className="stpb"
        aria-label={T('step_inc')}
        aria-disabled={atMax ? 'true' : undefined}
        onClick={() => move(1)}
      >
        <Icon name="plus" />
      </button>
    </div>
  )
}
