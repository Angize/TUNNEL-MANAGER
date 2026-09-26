import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import Stepper from '../../../components/Stepper.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { desyncOk, dsTtlUsed } from './gates.js'
import { desyncModes } from './presets.js'
import { limitErr } from './validate.js'
import { T } from '../../../i18n/fa.js'

function Desync({ form, limits, patch }) {
  const ttlUsed = dsTtlUsed(form)

  return (
    <>
      <SwitchRow
        on={!!form.Desync}
        title={T('ds_t')}
        note={T('ds_d')}
        onToggle={() => patch({ Desync: !form.Desync })}
      />
      <Reveal show={!!form.Desync}>
        <div>
          <label>{T('ds_mode_lbl')}</label>
          <Seg2 label={T('ds_mode_lbl')}>
            {desyncModes().map((mode) => (
              <SegOpt
                key={mode.v}
                on={mode.v === form.DesyncMode}
                title={mode.t}
                sub={mode.s}
                onClick={() => patch({ DesyncMode: mode.v })}
              />
            ))}
          </Seg2>
          <div className="grid2">
            {ttlUsed ? (
              <Field label={T('ds_ttl_lbl')}>
                <Stepper
                  min={limits.fake_ttl[0]}
                  max={limits.fake_ttl[1]}
                  value={form.dsTtl}
                  onChange={(v) => patch({ dsTtl: v })}
                />
              </Field>
            ) : null}
            <Field label={T('ds_count_lbl')}>
              <Stepper
                min={limits.fake_count[0]}
                max={limits.fake_count[1]}
                value={form.dsCount}
                onChange={(v) => patch({ dsCount: v })}
              />
            </Field>
          </div>
          <WarnCap text={ttlUsed ? limitErr(form, 'dsTtl', limits) : ''} style={{ marginTop: 8 }} />
          <WarnCap text={limitErr(form, 'dsCount', limits)} style={{ marginTop: 8 }} />
          <WarnCap text={T('ds_ttl_cap')} style={{ marginTop: 8 }} />
          <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
            {T('ds_note')}
          </div>
        </div>
      </Reveal>
    </>
  )
}

export default function DesyncSection(props) {
  return (
    <Reveal show={desyncOk(props.form)}>
      <Desync {...props} />
    </Reveal>
  )
}
