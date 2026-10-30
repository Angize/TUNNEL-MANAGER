import Field from '../../../components/Field.jsx'
import Icon from '../../../components/Icon.jsx'
import Reveal from '../../../components/Reveal.jsx'
import Select from '../../../components/Select.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import RotIpPool from './RotIpPool.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { cdnPathOff, edgeIpCount } from './gates.js'
import { poolRotateItems } from './presets.js'
import { toast } from '../../../lib/toast.js'
import { T, TF } from '../../../i18n/fa.js'

function edgeFronts(fronts, form, at) {
  const mine = (form.edges[at] || {}).node
  const other = (form.edges[1 - at] || {}).node
  return (fronts || []).filter(
    (f) =>
      f.id !== form.aNode && f.id !== form.bNode && f.id !== other && ((f.online && !f.hidden) || f.id === mine)
  )
}

function edgePatch(form, at, next) {
  return { edges: form.edges.map((e, i) => (i === at ? { ...e, ...next } : e)) }
}

function EdgeIps({ form, at, picked, patch }) {
  const ips = picked.ips
  const edge = form.edges[at]
  const chosen = edge.ips.length ? edge.ips : ips.filter((ip) => ip === picked.host)
  const toggle = (ip, count) => {
    if (chosen.includes(ip)) {
      if (count <= 1) {
        toast(T('pedge_keep_one'), 'err')
        return
      }
      patch(edgePatch(form, at, { ips: chosen.filter((x) => x !== ip) }))
    } else patch(edgePatch(form, at, { ips: ips.filter((x) => x === ip || chosen.includes(x)) }))
  }

  return (
    <div style={{ marginTop: 10 }}>
      <RotIpPool
        label={T('pedge_ips_lbl')}
        ips={ips}
        selected={Object.fromEntries(chosen.map((ip) => [ip, true]))}
        onToggle={toggle}
      />
    </div>
  )
}

function EdgePick({ form, at, live, label, patch }) {
  const edge = form.edges[at]
  const items = live.map((f) => ({ v: f.id, label: f.name, sub: form.Tr === 'ws' ? f.host + ':' + f.port : f.host }))
  const picked = live.find((f) => f.id === edge.node)

  return (
    <div style={{ marginTop: 8 }}>
      <Field
        label={label}
        hint={
          picked && form.Tr === 'ws' ? (
            <>
              {T('pedge_decoy_lbl') + ' '}
              <span className="mono" dir="ltr">
                {picked.decoy}
              </span>
            </>
          ) : null
        }
      >
        <Select
          items={items}
          value={edge.node}
          placeholder={T('select')}
          onChange={(v) => patch(edgePatch(form, at, { node: v, ips: [] }))}
        />
      </Field>
      {picked && picked.ips.length > 1 ? <EdgeIps form={form} at={at} picked={picked} patch={patch} /> : null}
      <WarnCap text={picked && form.Tr !== 'ws' && !picked.nft ? TF('pedge_no_nft', { n: picked.name }) : ''} style={{ marginTop: 8 }} />
    </div>
  )
}

function legend(form) {
  if (form.Tr === 'ws') return [T('pedge_leg_ws_in'), TF('pedge_leg_ws_out', { c: form.Cdn.toUpperCase() })]
  if (form.Tr !== 'raw') return [TF('pedge_leg_in', { c: form.Tr.toUpperCase() }), T('pedge_leg_same')]
  const up = form.RawProfile.toUpperCase()
  const down = form.RawProfileDown.toUpperCase()
  return [
    up === down ? TF('pedge_leg_in', { c: 'RAW ' + up }) : TF('pedge_leg_raw2', { u: up, d: down }),
    T('pedge_leg_same'),
  ]
}

function PathNode({ role, name, ip, mid }) {
  return (
    <div className={'epn' + (mid ? ' mid' : '')}>
      <small>{role}</small>
      <b>
        <bdi>{name}</bdi>
      </b>
      <code>{ip}</code>
    </div>
  )
}

function EdgePath({ form, fronts, ends }) {
  const edge = (fronts || []).find((f) => f.id === form.edges[0].node)
  const ip = form.edges[0].ips[0] || (edge && edge.host) || ''
  const legs = legend(form)
  const arrow = (
    <span className="epa">
      <Icon name="arrows" />
    </span>
  )

  return (
    <>
      <div className="epath">
        <PathNode role={T('client')} name={ends.client.name} ip={ends.client.ip} />
        {arrow}
        <PathNode role={T('pedge_node')} name={edge ? edge.name : '—'} ip={ip} mid />
        {arrow}
        <PathNode role={T('server')} name={ends.server.name} ip={ends.server.ip} />
      </div>
      <div className="eplegend">
        <div>{T('pedge_leg1') + ': ' + legs[0]}</div>
        <div>{T('pedge_leg2') + ': ' + legs[1]}</div>
      </div>
    </>
  )
}

export default function EdgeRoute({ form, fronts, ends, patch }) {
  const firstLive = edgeFronts(fronts, form, 0)
  const secondLive = form.EdgeOn ? edgeFronts(fronts, form, 1) : []

  const setRoute = (on) => {
    if (on === form.EdgeOn) return
    if (!on) {
      patch({ EdgeOn: false, edges: [], WsTls: false })
      return
    }
    patch({
      ...cdnPathOff(form),
      EdgeOn: true,
      SelfEch: false,
      wsHost: '',
      edges: [{ node: firstLive.length ? firstLive[0].id : '', ips: [] }],
      rot: { ...form.rot, on: false },
    })
  }

  const toggleSecond = () => {
    if (form.edges.length > 1) {
      patch({ edges: form.edges.slice(0, 1) })
    } else if (secondLive.length) {
      patch({ edges: [form.edges[0], { node: secondLive[0].id, ips: [] }] })
    } else toast(T('pedge_no_second'), 'err')
  }

  const count = edgeIpCount(form, fronts)

  return (
    <>
      <label>{T('pedge_route_lbl')}</label>
      <Seg2 label={T('pedge_route_lbl')}>
        <SegOpt on={!form.EdgeOn} title={T('pedge_direct_t')} sub={T('pedge_direct_d')} onClick={() => setRoute(false)} />
        <SegOpt on={form.EdgeOn} title={T('pedge_t')} sub={T('pedge_d')} onClick={() => setRoute(true)} />
      </Seg2>
      <Reveal show={form.EdgeOn}>
        {form.EdgeOn ? (
          <div>
            {firstLive.length ? (
              <EdgePick form={form} at={0} live={firstLive} label={T('pedge_pick_lbl')} patch={patch} />
            ) : (
              <div className="fldhint">{T('pedge_none')}</div>
            )}
            <EdgePath form={form} fronts={fronts} ends={ends} />
            <SwitchRow
              on={form.edges.length > 1}
              title={T('pedge2_t')}
              note={T('pedge2_d')}
              onToggle={toggleSecond}
            />
            <Reveal show={form.edges.length > 1}>
              {form.edges.length > 1 ? (
                <EdgePick form={form} at={1} live={secondLive} label={T('pedge2_pick_lbl')} patch={patch} />
              ) : null}
            </Reveal>
            <Reveal show={count > 1}>
              <Field label={T('rot_int_lbl')} hint={T('pedge_ips_note')}>
                <Select
                  items={poolRotateItems()}
                  value={form.edgeRotate}
                  placeholder={T('rot_int_lbl')}
                  onChange={(v) => patch({ edgeRotate: +v })}
                />
              </Field>
            </Reveal>
            <WarnCap tone="gold" text={count === 1 ? T('pedge_one_ip') : ''} style={{ marginTop: 8 }} />
          </div>
        ) : null}
      </Reveal>
    </>
  )
}
