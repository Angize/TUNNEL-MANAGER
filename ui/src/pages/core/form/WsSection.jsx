import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import RichText from '../../../components/RichText.jsx'
import { Tile, Tiles, WarnCap } from './controls.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsPool from './WsPool.jsx'
import { cdnShapeOn, wsProfOf } from './gates.js'
import { CDN_FIELD_NAMES, cdnLabel, cdnShape, wsProfiles } from './presets.js'
import { cdnShapeErr } from './validate.js'
import { T } from '../../../i18n/fa.js'
import { LTR_TEXT } from '../../../lib/form.js'

function Shape({ form, enums, patch }) {
  const shape = cdnShape(enums)
  const uploadOnly = form.Cdn === 'http'

  return (
    <div style={{ marginBottom: 8 }}>
      <label style={{ marginTop: 2 }}>{T('cdn_shape_lbl')}</label>
      <div
        role="group"
        aria-label={T('cdn_shape_lbl')}
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
            <Field
              key={name}
              className="cshape"
              label={
                <>
                  {cdnLabel(name)}{' '}
                  <span className="muted" dir="ltr">
                    {field.lo + '–' + field.hi}
                  </span>
                </>
              }
              style={{
                display: hidden ? 'none' : 'flex',
                flexDirection: 'column',
                minWidth: 0,
              }}
            >
              <NumberInput
                value={form.cdn[name]}
                onChange={(v) => patch({ cdn: { ...form.cdn, [name]: v } })}
              />
            </Field>
          )
        })}
      </div>
      <WarnCap text={cdnShapeErr(form, enums)} />
    </div>
  )
}

function CdnShape(props) {
  return (
    <Reveal show={cdnShapeOn(props.form)}>
      <Shape {...props} />
    </Reveal>
  )
}

function Ws({ form, cfg, sides, lid, live, patch }) {
  const current = wsProfOf(form.Cdn)

  return (
    <div>
      <label>{T('ws_prof_lbl')}</label>
      <Tiles p3 label={T('ws_prof_lbl')}>
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
      <WorkersSection form={form} cfg={cfg} sides={sides} patch={patch} />
      <CdnShape form={form} enums={cfg.enums} patch={patch} />
      <SwitchRow
        on={form.pool.pool}
        title={T('ws_pool_t')}
        note={T('ws_pool_d')}
        onToggle={() => patch({ pool: { ...form.pool, pool: !form.pool.pool } })}
      />
      <Reveal show={form.pool.pool}>
        <WsPool
          form={form}
          enums={cfg.enums}
          lid={lid}
          live={live}
          patch={patch}
        />
      </Reveal>
      <Reveal show={!form.pool.pool}>
        <div style={{ marginTop: 12 }}>
          <Field label={T('ws_host_lbl')}>
            <input
              {...LTR_TEXT}
              placeholder={T('ph_cdn_domain')}
              value={form.wsHost}
              onChange={(e) => patch({ wsHost: e.target.value })}
            />
          </Field>
          <Field label={T(form.WsTls ? 'ws_edge_lbl_wss' : 'ws_edge_lbl')}>
            <input
              {...LTR_TEXT}
              className="mono"
              placeholder={T(form.WsTls ? 'cf_edge_ph_tls' : 'cf_edge_ph_plain')}
              value={form.wsEdge}
              onChange={(e) => patch({ wsEdge: e.target.value })}
            />
          </Field>
        </div>
      </Reveal>
      <Field label={T('ws_path_lbl')}>
        <input
          {...LTR_TEXT}
          placeholder="/"
          value={form.wsPath}
          onChange={(e) => patch({ wsPath: e.target.value })}
        />
      </Field>
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 7 }}>
        <RichText text={T('ws_note')} />
      </div>
    </div>
  )
}

export default function WsSection(props) {
  return (
    <Reveal show={props.form.Tr === 'ws'}>
      <Ws {...props} />
    </Reveal>
  )
}
