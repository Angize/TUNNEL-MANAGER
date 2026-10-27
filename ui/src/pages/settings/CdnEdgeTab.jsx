import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import Select from '../../components/Select.jsx'
import SwitchRow from '../../components/SwitchRow.jsx'
import Reveal from '../../components/Reveal.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
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
    sub: [e.host, e.on ? TF('edge_port_note', { p: e.port }) : '', edgeState(e)[1]].filter(Boolean).join(' · '),
  }))
}

function EdgeCard({ edge, onToggle, onSave, busy }) {
  const [decoy, setDecoy] = useState(edge.decoy)
  const [port, setPort] = useState(String(edge.port))
  const n = Number(port)
  const portError = port && n >= 1 && n <= 65535 ? '' : T('edge_port_bad')
  const decoyError = decoy.trim() ? '' : T('edge_decoy_bad')
  const [tone, chip] = edgeState(edge)

  useEffect(() => {
    setDecoy(edge.decoy)
    setPort(String(edge.port))
  }, [edge.decoy, edge.port])

  return (
    <div className={'edgerow' + (edge.on ? ' open' : '')}>
      <div className="edgehd">
        <SwitchRow
          on={edge.on}
          locked={busy}
          title={edge.name}
          note={edge.host + (edge.on ? ' · ' + TF('edge_port_note', { p: edge.port }) : '')}
          onToggle={() => onToggle(edge)}
        />
        <span className={'cdnchip ' + tone}>{chip}</span>
      </div>
      <Reveal show={edge.on}>
        <div className="edgebody">
          <div className="edgegrid">
            <Field label={T('edge_decoy')} hint={T('edge_decoy_hint')} error={decoyError}>
              <input value={decoy} onChange={(e) => setDecoy(e.target.value)} dir="ltr" spellCheck={false} />
            </Field>
            <Field label={T('edge_port')} error={portError}>
              <input value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ''))} dir="ltr" inputMode="numeric" />
            </Field>
          </div>
          <div className="edgewarn">
            <Icon name="warn" />
            <span>{T('edge_decoy_warn')}</span>
          </div>
          <div className="edgeacts">
            <span className="grow" />
            <button
              type="button"
              className="btn"
              disabled={busy || !!portError || !!decoyError}
              onClick={() => onSave(edge, decoy.trim().toLowerCase(), n)}
            >
              {T('edge_save')}
            </button>
          </div>
        </div>
      </Reveal>
    </div>
  )
}

export default function CdnEdgeTab() {
  const [edges, setEdges] = useState(null)
  const [pick, setPick] = useState('')
  const [busy, setBusy] = useState([])
  const box = useRef(null)
  useRiseIn(box, true)

  const load = async () => {
    const r = await apiPost('cdn-edge', { act: 'state' })
    if (r.ok) {
      const list = r.d.edges || []
      setEdges(list)
      setPick((v) => v || (list.find((e) => e.on) || {}).id || '')
    } else {
      toast(postError(r), 'err')
      setEdges((v) => v || [])
    }
  }

  const done = (r, okKey) => {
    if (!r.ok) toast(postError(r), 'err')
    else if (r.d.msg) toast(translateError(r.d.msg), 'err')
    else toast(T(okKey))
  }

  useEffect(() => {
    load()
  }, [])

  const run = async (edge, body, okKey) => {
    setBusy((v) => v.concat(edge.id))
    const r = await apiPost('cdn-edge', { id: edge.id, ...body })
    if (r.ok) setEdges(r.d.edges)
    done(r, okKey)
    setBusy((v) => v.filter((x) => x !== edge.id))
  }

  const toggle = (edge) => run(edge, { act: edge.on ? 'off' : 'on' }, edge.on ? 'edge_toast_off' : 'edge_toast_on')

  const save = (edge, decoy, port) => run(edge, { act: 'on', decoy, port }, 'edge_toast_saved')

  const on = (edges || []).filter((e) => e.on)
  const picked = (edges || []).find((e) => e.id === pick)

  return (
    <div className="cdnedge" ref={box}>
      <SettingsGroup icon="shield" titleKey="edge_title" chipKey="edge_sub" tone="">
        <p className="edgeintro">{T('edge_intro')}</p>
        {edges === null ? (
          <p className="edgemuted">{T('edge_loading')}</p>
        ) : !edges.length ? (
          <p className="edgemuted">{T('edge_no_nodes')}</p>
        ) : (
          <>
            <Field label={T('edge_pick')}>
              <Select items={edgeItems(edges)} value={pick} placeholder={T('edge_pick_ph')} onChange={setPick} />
            </Field>
            {picked ? (
              <EdgeCard key={picked.id} edge={picked} busy={busy.includes(picked.id)} onToggle={toggle} onSave={save} />
            ) : (
              <p className="edgemuted">{T('edge_pick_hint')}</p>
            )}
          </>
        )}
        {on.length ? <p className="edgecount">{TF('edge_active_count', { n: on.length })}</p> : null}
      </SettingsGroup>
    </div>
  )
}
