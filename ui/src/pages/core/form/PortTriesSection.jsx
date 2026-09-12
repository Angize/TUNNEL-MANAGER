import { WarnCap } from './controls.jsx'
import { portTriesOn } from './gates.js'
import { portTriesRangeErr } from './validate.js'
import { PORT_TRIES_MAX } from './presets.js'
import { rangeLabel } from '../../../lib/form.js'
import { T } from '../../../i18n/fa.js'

export default function PortTriesSection({ form, enums, patch }) {
  if (!portTriesOn(form, enums)) return null

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">{rangeLabel(T('porttries_lbl'), 1, PORT_TRIES_MAX)}</label>
      <input
        className="mono"
        inputMode="numeric"
        maxLength={2}
        placeholder="2"
        style={{ textAlign: 'center', direction: 'ltr' }}
        value={form.portTries}
        onChange={(e) => patch({ portTries: e.target.value })}
      />
      <WarnCap text={portTriesRangeErr(form)} style={{ marginTop: 8 }} />
    </div>
  )
}
