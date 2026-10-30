import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwapCascade from '../../../components/SwapCascade.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import { Tile, Tiles, WarnCap } from './controls.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsPool from './WsPool.jsx'
import CdnHostField from './CdnHostField.jsx'
import { cdnAuto } from '../../../lib/cdn.js'
import { cdnPathOff, cdnShapeOn, wsProfOf } from './gates.js'
import { CDN_FIELD_NAMES, cdnLabel, cdnShape, wsProfiles } from './presets.js'
import { cdnShapeErr } from './validate.js'
import { T } from '../../../i18n/fa.js'
import { LTR_TEXT, rangeLabel } from '../../../lib/form.js'

function Shape({ form, enums, patch }) {
  const shape = cdnShape(enums)
  const uploadOnly = form.Cdn === 'http'

  return (
    <div style={{ marginBottom: 8 }}>
      <label>{T('cdn_shape_lbl')}</label>
      <div
        role="group"
        aria-label={T('cdn_shape_lbl')}
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))',
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
              label={rangeLabel(cdnLabel(name), field.lo, field.hi)}
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
      {uploadOnly ? <div className="fldhint">{T('cdn_uprate_hint')}</div> : null}
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

function Ws({ form, cfg, sides, lid, live, cdnKeys, cdnOwners, serverIp, onCdnMade, patch }) {
  const current = wsProfOf(form.Cdn)

  const toggleSelfEch = () => {
    if (form.SelfEch) {
      patch({ SelfEch: false, WsTls: false })
    } else {
      patch({ ...cdnPathOff(form), Cdn: form.Cdn === 'grpc' ? 'ws' : form.Cdn, SelfEch: true })
    }
  }

  return (
    <div>
      <label>{T('ws_prof_lbl')}</label>
      <Tiles p3 label={T('ws_prof_lbl')}>
        {wsProfiles()
          .filter((profile) => !form.SelfEch || profile.v !== 'grpc')
          .map((profile) => (
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
      <Reveal show={!form.EdgeOn}>
        <SwitchRow on={form.SelfEch} title={T('selfech_t')} note={T('selfech_d')} onToggle={toggleSelfEch} />
      </Reveal>
      <Reveal show={!!form.SelfEch}>
        <div style={{ marginTop: 8 }}>
          <Field label={T('selfech_inner_lbl')}>
            <input
              {...LTR_TEXT}
              placeholder={T('selfech_inner_ph')}
              value={form.wsHost}
              onChange={(e) => patch({ wsHost: e.target.value })}
            />
          </Field>
          <Field label={T('selfech_public_lbl')} style={{ marginTop: 8 }}>
            <input
              {...LTR_TEXT}
              placeholder={T('selfech_public_ph')}
              value={form.echPublic}
              onChange={(e) => patch({ echPublic: e.target.value })}
            />
          </Field>
          <div className="fldhint">{T('selfech_note')}</div>
        </div>
      </Reveal>
      <Reveal show={!form.SelfEch && !form.EdgeOn}>
        <>
          <SwitchRow
            on={form.pool.pool}
            title={T('ws_pool_t')}
            note={T('ws_pool_d')}
            onToggle={() => patch({ pool: { ...form.pool, pool: !form.pool.pool } })}
          />
          <SwapCascade value={!!form.pool.pool}>
            <Reveal show={form.pool.pool}>
              <WsPool
                edges={cdnKeys && cdnKeys.edges}
                keys={cdnKeys}
                owners={cdnOwners}
                serverIp={serverIp}
                onCdnMade={onCdnMade}
                form={form}
                enums={cfg.enums}
                lid={lid}
                live={live}
                patch={patch}
              />
            </Reveal>
            <Reveal show={!form.pool.pool}>
              <div style={{ marginTop: 12 }}>
                <CdnHostField form={form} keys={cdnKeys} serverIp={serverIp} patch={patch} onMade={onCdnMade} />
              </div>
            </Reveal>
          </SwapCascade>
        </>
      </Reveal>
      <Field label={T('ws_path_lbl')}>
        <input
          {...LTR_TEXT}
          placeholder="/"
          value={form.wsPath}
          onChange={(e) => patch({ wsPath: e.target.value })}
        />
      </Field>
      <Reveal show={!cdnAuto(form) && !form.SelfEch && !form.EdgeOn}>
        <div className="fldhint">{T('ws_note')}</div>
      </Reveal>
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
