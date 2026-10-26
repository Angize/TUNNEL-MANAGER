import { useEffect, useId, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import SwitchRow from '../../components/SwitchRow.jsx'
import Reveal from '../../components/Reveal.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { T, TF } from '../../i18n/fa.js'

const EDGE_DECOY = 'www.google.com'

function EdgeChip({ edge }) {
  if (!edge.on) return <span className="cdnchip off">{T('edge_chip_off')}</span>
  if (!edge.online) return <span className="cdnchip bad">{T('edge_chip_down')}</span>
  if (edge.front === false) return <span className="cdnchip bad">{T('edge_chip_front_down')}</span>
  if (!edge.routes) return <span className="cdnchip warn">{T('edge_chip_idle')}</span>
  return <span className="cdnchip ok">{TF('edge_chip_routes', { n: edge.routes })}</span>
}

function EdgeRow({ edge, onToggle, onSave, busy }) {
  const [open, setOpen] = useState(false)
  const [decoy, setDecoy] = useState(edge.decoy || EDGE_DECOY)
  const [port, setPort] = useState(String(edge.port || 443))
  const bodyId = useId()
  const n = Number(port)
  const portError = port && n >= 1 && n <= 65535 ? '' : T('edge_port_bad')
  const decoyError = decoy.trim() ? '' : T('edge_decoy_bad')

  useEffect(() => {
    setDecoy(edge.decoy || EDGE_DECOY)
    setPort(String(edge.port || 443))
  }, [edge.decoy, edge.port, edge.saved])

  return (
    <div className={'edgerow' + (open && edge.on ? ' open' : '')}>
      <div className="edgehd">
        <SwitchRow
          on={edge.on}
          locked={busy}
          title={edge.name}
          note={edge.host + (edge.on ? ' · ' + TF('edge_port_note', { p: edge.port }) : '')}
          onToggle={() => onToggle(edge)}
        />
        <EdgeChip edge={edge} />
        {edge.on ? (
          <button
            type="button"
            className="edgecfg"
            aria-expanded={open}
            aria-controls={bodyId}
            onClick={() => setOpen((v) => !v)}
            aria-label={TF('edge_settings_of', { n: edge.name })}
            title={T('edge_settings')}
          >
            <Icon name="chev" />
          </button>
        ) : null}
      </div>
      <Reveal show={open && edge.on}>
        <div className="edgebody" id={bodyId}>
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
  const [busy, setBusy] = useState([])
  const box = useRef(null)
  useRiseIn(box, true)

  const load = async () => {
    const r = await apiPost('cdn-edge', { act: 'state' })
    if (r.ok) {
      setEdges(r.d.edges || [])
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
    if (r.ok) await load()
    done(r, okKey)
    setBusy((v) => v.filter((x) => x !== edge.id))
  }

  const toggle = (edge) => run(edge, { act: edge.on ? 'off' : 'on' }, edge.on ? 'edge_toast_off' : 'edge_toast_on')

  const save = (edge, decoy, port) => run(edge, { act: 'on', decoy, port }, 'edge_toast_saved')

  const on = (edges || []).filter((e) => e.on)

  return (
    <div className="cdnedge" ref={box}>
      <SettingsGroup icon="shield" titleKey="edge_title" chipKey="edge_sub" tone="">
        <p className="edgeintro">{T('edge_intro')}</p>
        {edges === null ? (
          <p className="edgemuted">{T('edge_loading')}</p>
        ) : !edges.length ? (
          <p className="edgemuted">{T('edge_no_nodes')}</p>
        ) : (
          <div className="edgelist">
            {edges.map((e) => (
              <EdgeRow key={e.id} edge={e} busy={busy.includes(e.id)} onToggle={toggle} onSave={save} />
            ))}
          </div>
        )}
        {on.length ? <p className="edgecount">{TF('edge_active_count', { n: on.length })}</p> : null}
      </SettingsGroup>
    </div>
  )
}
