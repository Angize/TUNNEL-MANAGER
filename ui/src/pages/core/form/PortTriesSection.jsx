import { TglBox, WarnCap } from './controls.jsx'
import { portTriesOn, wsPoolOn } from './gates.js'
import { portTriesRangeErr } from './validate.js'
import { PORT_TRIES_MAX } from './presets.js'
import { rangeLabel } from '../../../lib/form.js'
import { T } from '../../../i18n/fa.js'

export default function PortTriesSection({ form, enums, patch }) {
  const roll = wsPoolOn(form)
  const tries = portTriesOn(form, enums)
  if (!roll && !tries) return null

  return (
    <>
      {roll ? (
        <TglBox
          on={!!form.pool.portRoll}
          title={T('pool_roll_t')}
          note={T('pool_roll_d')}
          gap={11}
          onClick={() => patch({ pool: { ...form.pool, portRoll: !form.pool.portRoll } })}
        />
      ) : null}
      {tries ? (
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
      ) : null}
    </>
  )
}
