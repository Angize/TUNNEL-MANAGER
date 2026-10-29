import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import Field from '../../../components/Field.jsx'
import Stepper from '../../../components/Stepper.jsx'
import { WarnCap } from './controls.jsx'
import { irotLive, rawFlowID } from './gates.js'
import BandSection from './BandSection.jsx'
import { RAW_SPROT_MAX, SPROT_DEFAULT } from './presets.js'
import { intOf, irotErr } from './validate.js'
import { rangeLabel } from '../../../lib/form.js'
import { T } from '../../../i18n/fa.js'

function FlowId({ form, cfg, patch }) {
  const live = irotLive(form, cfg.enums)

  const toggle = () => {
    if (live) {
      patch({ Irot: false })
      return
    }
    const next = { Irot: true }
    if (!intOf(form.rawIrot)) next.rawIrot = String(SPROT_DEFAULT)
    patch(next)
  }

  return (
    <div style={{ marginTop: 12 }}>
      <SwitchRow on={live} title={T('raw_irot_t')} note={T('raw_irot_d')} onToggle={toggle} />
      <Reveal show={live}>
        <div>
          <Field label={rangeLabel(T('raw_sprot_lbl'), 1, RAW_SPROT_MAX)}>
            <Stepper
              min={1}
              max={RAW_SPROT_MAX}
              placeholder={String(SPROT_DEFAULT)}
              value={form.rawIrot}
              onChange={(v) => patch({ rawIrot: v })}
            />
          </Field>
          <WarnCap
            text={form.RawProfile === 'gre' ? T('raw_irot_gre') : T('raw_irot_icmp')}
            tone={form.RawProfile === 'gre' ? 'gold' : ''}
            style={{ marginTop: 8 }}
          />
          <WarnCap text={irotErr(form, cfg.enums)} style={{ marginTop: 8 }} />
          <BandSection form={form} cfg={cfg} patch={patch} />
        </div>
      </Reveal>
    </div>
  )
}

export default function FlowIdSection(props) {
  return (
    <Reveal show={rawFlowID(props.form, props.cfg.enums)}>
      <FlowId {...props} />
    </Reveal>
  )
}
