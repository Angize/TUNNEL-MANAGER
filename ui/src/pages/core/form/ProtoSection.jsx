import { useId } from 'react'
import Reveal from '../../../components/Reveal.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { intOf, rawProtoErr } from './validate.js'
import { protoVisOn } from './gates.js'
import { T } from '../../../i18n/fa.js'

function Proto({ form, enums, patch }) {
  const id = useId()

  const current = intOf(form.rawProto)
  const label = T('raw_proto_lbl')

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first" htmlFor={id}>
        {label}
      </label>
      <Seg2 label={label} style={{ marginBottom: 8 }}>
        <SegOpt
          on={current === 253}
          title="253"
          sub={T('raw_proto_native')}
          onClick={() => patch({ rawProto: '253' })}
        />
        <SegOpt
          on={current === 252}
          title="252"
          sub={T('raw_proto_free')}
          onClick={() => patch({ rawProto: '252' })}
        />
      </Seg2>
      <NumberInput
        id={id}
        className="mono"
        maxLength={3}
        placeholder="253"
        style={{ textAlign: 'center', direction: 'ltr' }}
        value={form.rawProto}
        onChange={(v) => patch({ rawProto: v })}
      />
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
        {T('raw_proto_hint')}
      </div>
      <WarnCap text={rawProtoErr(form.rawProto, enums)} style={{ marginTop: 8 }} />
    </div>
  )
}

export default function ProtoSection(props) {
  return (
    <Reveal show={protoVisOn(props.form)}>
      <Proto {...props} />
    </Reveal>
  )
}
