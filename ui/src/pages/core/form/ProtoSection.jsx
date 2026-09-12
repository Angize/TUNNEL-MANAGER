import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { rawProtoOwner } from './validate.js'
import { protoVisOn } from './gates.js'
import { T } from '../../../i18n/fa.js'

export default function ProtoSection({ form, enums, patch }) {
  if (!protoVisOn(form)) return null

  const current = parseInt(form.rawProto, 10)
  const owner = rawProtoOwner(current, enums)
  const warn = owner
    ? T('raw_proto_owned').replace('{n}', current).split('{p}').join(owner)
    : ''

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">{T('raw_proto_lbl')}</label>
      <Seg2 style={{ marginBottom: 8 }}>
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
      <input
        className="mono"
        inputMode="numeric"
        maxLength={3}
        placeholder="253"
        style={{ textAlign: 'center', direction: 'ltr' }}
        value={form.rawProto}
        onChange={(e) => patch({ rawProto: e.target.value })}
      />
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
        {T('raw_proto_hint')}
      </div>
      <WarnCap text={warn} style={{ marginTop: 8 }} />
    </div>
  )
}
