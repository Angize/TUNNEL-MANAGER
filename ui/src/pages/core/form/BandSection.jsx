import { WarnCap } from './controls.jsx'
import { bandOn } from './gates.js'
import { bandErr } from './validate.js'
import { RAW_ROT_HI, RAW_ROT_LO } from '../carrier.js'
import { T } from '../../../i18n/fa.js'

export default function BandSection({ form, enums, patch }) {
  if (!bandOn(form, enums)) return null
  const parts = T('band_lbl').split('{r}')

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">
        {parts[0]}
        <span className="iso">{RAW_ROT_LO + '-' + RAW_ROT_HI}</span>
        {parts[1]}
      </label>
      <div className="grid2">
        <div>
          <input
            className="mono"
            inputMode="numeric"
            maxLength={5}
            placeholder={String(RAW_ROT_LO)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.bandLo}
            onChange={(e) => patch({ bandLo: e.target.value })}
          />
        </div>
        <div>
          <input
            className="mono"
            inputMode="numeric"
            maxLength={5}
            placeholder={String(RAW_ROT_HI)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.bandHi}
            onChange={(e) => patch({ bandHi: e.target.value })}
          />
        </div>
      </div>
      <WarnCap text={bandErr(form)} style={{ marginTop: 8 }} />
    </div>
  )
}
