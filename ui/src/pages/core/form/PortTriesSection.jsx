import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import Stepper from '../../../components/Stepper.jsx'
import { WarnCap } from './controls.jsx'
import { portTriesOn } from './gates.js'
import { portTriesRangeErr } from './validate.js'
import { rangeLabel } from '../../../lib/form.js'
import { T } from '../../../i18n/fa.js'

function Tries({ form, cfg, patch }) {
  return (
    <Field
      label={rangeLabel(T('porttries_lbl'), ...cfg.limits.port_tries)}
      first
      style={{ marginTop: 12 }}
    >
      <Stepper
        min={cfg.limits.port_tries[0]}
        max={cfg.limits.port_tries[1]}
        placeholder={String(cfg.defaults.port_tries)}
        value={form.portTries}
        onChange={(v) => patch({ portTries: v })}
      />
      <WarnCap text={portTriesRangeErr(form, cfg.limits)} style={{ marginTop: 8 }} />
    </Field>
  )
}

export default function PortTriesSection(props) {
  return (
    <Reveal show={portTriesOn(props.form, props.cfg.enums)}>
      <Tries {...props} />
    </Reveal>
  )
}
