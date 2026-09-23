import RichText from '../../../components/RichText.jsx'
import { TglBox, Tile, Tiles, WarnCap } from './controls.jsx'
import WsPool from './WsPool.jsx'
import { cdnShapeOn, wsProfOf } from './gates.js'
import { CDN_FIELD_NAMES, cdnLabel, cdnShape, wsProfiles } from './presets.js'
import { cdnShapeErr } from './validate.js'
import { T } from '../../../i18n/fa.js'

function CdnShape({ form, enums, patch }) {
  if (!cdnShapeOn(form)) return null
  const shape = cdnShape(enums)
  const uploadOnly = form.Cdn === 'http'

  return (
    <div style={{ marginBottom: 8 }}>
      <label style={{ marginTop: 2 }}>{T('cdn_shape_lbl')}</label>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit,minmax(104px,1fr))',
          gap: 8,
        }}
      >
        {CDN_FIELD_NAMES.map((name) => {
          const field = shape[name]
          const hidden = name !== 'downw' && !uploadOnly
          return (
            <div
              key={name}
              style={{
                display: hidden ? 'none' : 'flex',
                flexDirection: 'column',
                minWidth: 0,
              }}
            >
              <label style={{ marginTop: 0, flex: 1 }}>
                {cdnLabel(name)}{' '}
                <span className="muted" dir="ltr">
                  {field.lo + '–' + field.hi}
                </span>
              </label>
              <input
                type="number"
                inputMode="numeric"
                min={field.lo}
                max={field.hi}
                value={form.cdn[name]}
                onChange={(e) => patch({ cdn: { ...form.cdn, [name]: e.target.value } })}
              />
            </div>
          )
        })}
      </div>
      <WarnCap text={cdnShapeErr(form, enums)} />
    </div>
  )
}

export default function WsSection({ form, cfg, tuning, lid, live, patch }) {
  if (form.Tr !== 'ws') return null
  const current = wsProfOf(form.Cdn)

  return (
    <div>
      <label>{T('ws_prof_lbl')}</label>
      <Tiles p3>
        {wsProfiles().map((profile) => (
          <Tile
            key={profile.v}
            on={profile.v === current}
            name={profile.v}
            meta={profile.m}
            onClick={() => patch({ Cdn: profile.v })}
          />
        ))}
      </Tiles>
      <CdnShape form={form} enums={cfg.enums} patch={patch} />
      <TglBox
        on={form.pool.pool}
        title={T('ws_pool_t')}
        note={T('ws_pool_d')}
        onClick={() => patch({ pool: { ...form.pool, pool: !form.pool.pool } })}
      />
      {form.pool.pool ? (
        <WsPool
          form={form}
          enums={cfg.enums}
          tuning={tuning}
          lid={lid}
          live={live}
          patch={patch}
        />
      ) : (
        <div style={{ marginTop: 11 }}>
          <label>{T('ws_host_lbl')}</label>
          <input
            dir="ltr"
            placeholder={T('ph_cdn_domain')}
            value={form.wsHost}
            onChange={(e) => patch({ wsHost: e.target.value })}
          />
          <label>{T(form.WsTls ? 'ws_edge_lbl_wss' : 'ws_edge_lbl')}</label>
          <input
            className="mono"
            dir="ltr"
            placeholder={T('ph_edge_ip')}
            value={form.wsEdge}
            onChange={(e) => patch({ wsEdge: e.target.value })}
          />
        </div>
      )}
      <label>{T('ws_path_lbl')}</label>
      <input
        dir="ltr"
        placeholder="/"
        value={form.wsPath}
        onChange={(e) => patch({ wsPath: e.target.value })}
      />
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 7 }}>
        <RichText text={T('ws_note')} />
      </div>
    </div>
  )
}
