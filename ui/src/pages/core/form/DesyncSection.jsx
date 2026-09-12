import { Seg2, SegOpt, TglBox, WarnCap } from './controls.jsx'
import { desyncOk, dsTtlUsed } from './gates.js'
import { desyncModes } from './presets.js'
import { T } from '../../../i18n/fa.js'

export default function DesyncSection({ form, patch }) {
  if (!desyncOk(form)) return null

  return (
    <>
      <TglBox
        on={!!form.Desync}
        title={T('ds_t')}
        note={T('ds_d')}
        gap={11}
        onClick={() => patch({ Desync: !form.Desync })}
      />
      {form.Desync ? (
        <div>
          <label>{T('ds_mode_lbl')}</label>
          <Seg2>
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
            {dsTtlUsed(form) ? (
              <div>
                <label>{T('ds_ttl_lbl')}</label>
                <input
                  dir="ltr"
                  inputMode="numeric"
                  value={form.dsTtl}
                  onChange={(e) => patch({ dsTtl: e.target.value })}
                />
              </div>
            ) : null}
            <div>
              <label>{T('ds_count_lbl')}</label>
              <input
                dir="ltr"
                inputMode="numeric"
                value={form.dsCount}
                onChange={(e) => patch({ dsCount: e.target.value })}
              />
            </div>
          </div>
          <WarnCap text={T('ds_ttl_cap')} style={{ marginTop: 8 }} />
          <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
            {T('ds_note')}
          </div>
        </div>
      ) : null}
    </>
  )
}
