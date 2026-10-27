import { useEffect, useId, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import Select from '../../components/Select.jsx'
import SwitchRow from '../../components/SwitchRow.jsx'
import Reveal from '../../components/Reveal.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Stepper from '../../components/Stepper.jsx'
import SaveLabel from '../../components/SaveLabel.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import { WarnCap } from '../core/form/controls.jsx'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { T, TF } from '../../i18n/fa.js'

function edgeState(edge) {
  if (!edge.on) return ['off', T('edge_chip_off')]
  if (!edge.online) return ['bad', T('edge_chip_down')]
  if (!edge.routes) return ['warn', T('edge_chip_idle')]
  if (!edge.front) return ['bad', T('edge_chip_front_down')]
  return ['ok', TF('edge_chip_routes', { n: edge.routes })]
}

function edgeItems(edges) {
  return [...edges.filter((e) => e.on), ...edges.filter((e) => !e.on)].map((e) => ({
    v: e.id,
    label: e.name,
    sub: [e.host, e.on ? TF('edges_port', { p: e.port }) : '', edgeState(e)[1]].filter(Boolean).join(' · '),
  }))
}

function EdgeCard({ edge, onToggle, onSave, busy }) {
  const [lo, hi] = useUiConfig().tuning_ranges.tcp_buf_mb
  const [decoy, setDecoy] = useState(edge.decoy)
  const [port, setPort] = useState(String(edge.port))
  const [buf, setBuf] = useState(String(edge.buf_mb))
  const n = Number(port)
  const mb = Number(buf)
  const portError = port && n >= 1 && n <= 65535 ? '' : T('edge_port_bad')
  const decoyError = decoy.trim() ? '' : T('edge_decoy_bad')
  const bufError = /^\d+$/.test(buf) && mb >= lo && mb <= hi ? '' : TF('edge_buf_bad', { lo, hi })

  useEffect(() => {
    setDecoy(edge.decoy)
    setPort(String(edge.port))
    setBuf(String(edge.buf_mb))
  }, [edge.decoy, edge.port, edge.buf_mb])

  return (
    <>
      <SwitchRow
        on={edge.on}
        locked={busy}
        title={T('edge_role')}
        note={<bdi>{edge.host}</bdi>}
        onToggle={() => onToggle(edge)}
      />
      <Reveal show={edge.on}>
        <div className="edgebody">
          <div className="edgegrid">
            <Field label={T('edge_decoy')} hint={T('edge_decoy_hint')} error={decoyError}>
              <input value={decoy} onChange={(e) => setDecoy(e.target.value)} dir="ltr" spellCheck={false} />
            </Field>
            <Field label={T('edge_port')} error={portError}>
              <NumberInput value={port} onChange={setPort} dir="ltr" />
            </Field>
          </div>
          <WarnCap tone="gold" text={T('edge_decoy_warn')} />
          <Field
            label={T('edge_buf')}
            hint={T(edge.routes && mb !== edge.buf_mb ? 'edge_buf_restart' : 'edge_buf_hint')}
            error={bufError}
          >
            <Stepper min={lo} max={hi} unit={T('set_u_mb')} value={buf} onChange={setBuf} />
          </Field>
          <div className="oprow">
            <button
              type="button"
              className="primary"
              disabled={busy || !!portError || !!decoyError || !!bufError}
              onClick={() => onSave(edge, decoy.trim().toLowerCase(), n, mb)}
            >
              <SaveLabel busy={busy}>{T('edge_save')}</SaveLabel>
            </button>
          </div>
        </div>
      </Reveal>
    </>
  )
}

function firstPick(edges) {
  const on = edges.filter((e) => e.on)
  return (on.find((e) => edgeState(e)[0] === 'bad') || on[0] || edges[0] || {}).id || ''
}

export default function CdnEdgeTab() {
  const [edges, setEdges] = useState(null)
  const [err, setErr] = useState('')
  const [pick, setPick] = useState('')
  const [busy, setBusy] = useState([])
  const pickId = useId()

  const load = async () => {
    setErr('')
    const r = await apiPost('cdn-edge', { act: 'state' })
    if (r.ok) {
      const list = r.d.edges || []
      setEdges(list)
      setPick((v) => v || firstPick(list))
    } else {
      setErr(postError(r))
    }
  }

  const done = (edge, r, okKey) => {
    if (!r.ok) toast(TF('edge_err_of', { n: edge.name, m: postError(r) }), 'err')
    else if (r.d.msg) toast(TF('edge_err_of', { n: edge.name, m: translateError(r.d.msg) }), 'err')
    else toast(T(okKey))
  }

  useEffect(() => {
    load()
  }, [])

  const run = async (edge, body, okKey) => {
    setBusy((v) => v.concat(edge.id))
    const r = await apiPost('cdn-edge', { id: edge.id, ...body })
    if (r.ok) setEdges(r.d.edges)
    done(edge, r, okKey)
    setBusy((v) => v.filter((x) => x !== edge.id))
  }

  const toggle = (edge) => run(edge, { act: edge.on ? 'off' : 'on' }, edge.on ? 'edge_toast_off' : 'edge_toast_on')

  const save = (edge, decoy, port, buf_mb) => run(edge, { act: 'on', decoy, port, buf_mb }, 'edge_toast_saved')

  const on = (edges || []).filter((e) => e.on)
  const bad = on.filter((e) => edgeState(e)[0] === 'bad').length
  const picked = (edges || []).find((e) => e.id === pick) || (edges || [])[0]
  const [tone, chip] = picked ? edgeState(picked) : ['', '']

  return (
    <div className="stpage cdnedge">
      <LoadBar on={edges === null && !err} />
      {edges === null && err ? (
        <div className="card loadfail">
          <span>{T('edge_load_failed') + ' ' + err}</span>
          <button type="button" className="ghost" onClick={load}>
            <Icon name="redo" />
            {T('retry')}
          </button>
        </div>
      ) : null}
      {edges ? (
        <SettingsGroup
          icon="shield"
          titleKey="edge_title"
          chip={edges.length ? (on.length ? TF('edge_on_n', { n: on.length }) : T('edge_none_on')) : ''}
          tone="sc-conn"
        >
          <p className="edgeintro">{T('edge_intro')}</p>
          {!picked ? (
            <p className="edgemuted">{T('edge_no_nodes')}</p>
          ) : (
            <>
              <WarnCap text={bad ? TF('edge_bad_count', { n: bad }) : ''} />
              <div className="edgepickhd">
                <label htmlFor={pickId}>{T('edge_pick')}</label>
                {picked.on ? <span className={'cdnchip ' + tone}>{chip}</span> : null}
              </div>
              <Select
                id={pickId}
                items={edgeItems(edges)}
                value={picked.id}
                placeholder={T('edge_pick_ph')}
                onChange={setPick}
              />
              <EdgeCard key={picked.id} edge={picked} busy={busy.includes(picked.id)} onToggle={toggle} onSave={save} />
            </>
          )}
        </SettingsGroup>
      ) : null}
    </div>
  )
}
