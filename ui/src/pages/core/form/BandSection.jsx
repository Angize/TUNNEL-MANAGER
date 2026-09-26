import { useId } from 'react'
import Reveal from '../../../components/Reveal.jsx'
import Field from '../../../components/Field.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import { WarnCap } from './controls.jsx'
import { bandOn } from './gates.js'
import { bandErr } from './validate.js'
import { RAW_ROT_HI, RAW_ROT_LO } from '../carrier.js'
import { T } from '../../../i18n/fa.js'

function Band({ form, cfg, patch }) {
  const id = useId()
  const parts = T('band_lbl').split('{r}')

  return (
    <div style={{ marginTop: 12 }} role="group" aria-labelledby={id}>
      <label className="first" id={id}>
        {parts[0]}
        <span className="iso">{RAW_ROT_LO + '-' + RAW_ROT_HI}</span>
        {parts[1]}
      </label>
      <div className="grid2">
        <Field label={T('cf_band_from')} className="cbandend">
          <NumberInput
            className="mono"
            maxLength={5}
            placeholder={String(RAW_ROT_LO)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.bandLo}
            onChange={(v) => patch({ bandLo: v })}
          />
        </Field>
        <Field label={T('cf_band_to')} className="cbandend">
          <NumberInput
            className="mono"
            maxLength={5}
            placeholder={String(RAW_ROT_HI)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.bandHi}
            onChange={(v) => patch({ bandHi: v })}
          />
        </Field>
      </div>
      <WarnCap text={bandErr(form, cfg.limits)} style={{ marginTop: 8 }} />
    </div>
  )
}

export default function BandSection(props) {
  return (
    <Reveal show={bandOn(props.form, props.cfg.enums)}>
      <Band {...props} />
    </Reveal>
  )
}
