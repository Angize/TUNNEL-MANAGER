import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwapCascade from '../../../components/SwapCascade.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import RichText from '../../../components/RichText.jsx'
import Select from '../../../components/Select.jsx'
import RotIpPool from './RotIpPool.jsx'
import { Tile, Tiles, WarnCap } from './controls.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsPool from './WsPool.jsx'
import CdnHostField from './CdnHostField.jsx'
import { cdnAuto } from '../../../lib/cdn.js'
import { cdnShapeOn, wsProfOf } from './gates.js'
import { CDN_FIELD_NAMES, cdnLabel, cdnShape, poolRotateItems, wsProfiles } from './presets.js'
import { cdnShapeErr } from './validate.js'
import { T } from '../../../i18n/fa.js'
import { LTR_TEXT } from '../../../lib/form.js'
import { toast } from '../../../lib/toast.js'

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

function edgeFronts(fronts, form) {
  return (fronts || []).filter(
    (f) => f.id !== form.aNode && f.id !== form.bNode && ((f.online && !f.hidden) || f.id === form.edgeNode)
  )
}

function EdgeIps({ form, picked, patch }) {
  const ips = picked.ips
  const chosen = form.edgeIps.length ? form.edgeIps : ips.filter((ip) => ip === picked.host)
  const toggle = (ip, count) => {
    if (chosen.includes(ip)) {
      if (count <= 1) {
        toast(T('pedge_keep_one'), 'err')
        return
      }
      patch({ edgeIps: chosen.filter((x) => x !== ip) })
    } else patch({ edgeIps: ips.filter((x) => x === ip || chosen.includes(x)) })
  }

  return (
    <div style={{ marginTop: 10 }}>
      <RotIpPool
        label={T('pedge_ips_lbl')}
        ips={ips}
        selected={Object.fromEntries(chosen.map((ip) => [ip, true]))}
        onToggle={toggle}
      />
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
        {T('pedge_ips_note')}
      </div>
      <Reveal show={chosen.length > 1}>
        <Field label={T('rot_int_lbl')}>
          <Select
            items={poolRotateItems()}
            value={form.edgeRotate}
            placeholder={T('rot_int_lbl')}
            onChange={(v) => patch({ edgeRotate: +v })}
          />
        </Field>
      </Reveal>
    </div>
  )
}

function PrivateEdge({ form, fronts, patch }) {
  const live = edgeFronts(fronts, form)
  const items = live.map((f) => ({ v: f.id, label: f.name, sub: f.host + ':' + f.port }))
  const picked = live.find((f) => f.id === form.edgeNode)

  return (
    <div style={{ marginTop: 8 }}>
      {items.length ? (
        <>
          <Field label={T('pedge_pick_lbl')}>
            <Select
              items={items}
              value={form.edgeNode}
              placeholder={T('select')}
              onChange={(v) => patch({ edgeNode: v, edgeIps: [] })}
            />
            {picked ? (
              <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
                {T('pedge_decoy_lbl')}{' '}
                <span className="mono" dir="ltr">
                  {picked.decoy}
                </span>
              </div>
            ) : null}
          </Field>
          {picked && picked.ips.length > 1 ? <EdgeIps form={form} picked={picked} patch={patch} /> : null}
        </>
      ) : (
        <div className="muted" style={{ fontSize: 12, lineHeight: 1.7 }}>
          {T('pedge_none')}
        </div>
      )}
      <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 7 }}>
        <RichText text={T('pedge_note')} />
      </div>
    </div>
  )
}

function Ws({ form, cfg, sides, lid, live, cdnKeys, cdnOwners, serverIp, onCdnMade, patch }) {
  const current = wsProfOf(form.Cdn)
  const fronts = cdnKeys && cdnKeys.fronts

  const cdnPathOff = {
    WsTls: true,
    Ech: false,
    EchProxy: false,
    SniSplit: false,
    cdnOwner: '',
    cdnZone: '',
    poolCdn: false,
    cdnEdgeAuto: true,
    wsEdge: '',
    pool: { ...form.pool, pool: false },
  }

  const toggleSelfEch = () => {
    if (form.SelfEch) {
      patch({ SelfEch: false, WsTls: false })
    } else {
      patch({ ...cdnPathOff, Cdn: form.Cdn === 'grpc' ? 'ws' : form.Cdn, SelfEch: true, EdgeOn: false, edgeNode: '' })
    }
  }

  const toggleEdge = () => {
    if (form.EdgeOn) {
      patch({ EdgeOn: false, edgeNode: '', edgeIps: [], WsTls: false })
    } else {
      const first = edgeFronts(fronts, form)[0]
      patch({ ...cdnPathOff, EdgeOn: true, edgeNode: first ? first.id : '', edgeIps: [], SelfEch: false, wsHost: '' })
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
      <SwitchRow
        on={form.SelfEch}
        title={T('selfech_t')}
        note={T('selfech_d')}
        onToggle={toggleSelfEch}
      />
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
          <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 7 }}>
            <RichText text={T('selfech_note')} />
          </div>
        </div>
      </Reveal>
      <SwitchRow on={form.EdgeOn} title={T('pedge_t')} note={T('pedge_d')} onToggle={toggleEdge} />
      <Reveal show={!!form.EdgeOn}>
        <PrivateEdge form={form} fronts={fronts} patch={patch} />
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
        <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 7 }}>
          <RichText text={T('ws_note')} />
        </div>
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
