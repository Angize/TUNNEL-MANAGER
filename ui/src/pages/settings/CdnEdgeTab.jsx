import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import SwitchRow from '../../components/SwitchRow.jsx'
import Reveal from '../../components/Reveal.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { T, TF } from '../../i18n/fa.js'

function EdgeChip({ edge }) {
  if (!edge.on) return <span className="cdnchip off">{T('edge_chip_off')}</span>
  if (!edge.routes) return <span className="cdnchip warn">{T('edge_chip_idle')}</span>
  return <span className="cdnchip ok">{TF('edge_chip_routes', { n: edge.routes })}</span>
}

function EdgeRow({ edge, onToggle, onSave, busy }) {
  const [open, setOpen] = useState(false)
  const [decoy, setDecoy] = useState(edge.decoy || 'www.google.com')
  const [port, setPort] = useState(String(edge.port || 443))

  useEffect(() => {
    setDecoy(edge.decoy || 'www.google.com')
    setPort(String(edge.port || 443))
  }, [edge.decoy, edge.port])

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
        {edge.on ? (
          <button
            type="button"
            className="edgecfg"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            title={T('edge_settings')}
          >
            <Icon name="chev" />
          </button>
        ) : (
          <EdgeChip edge={edge} />
        )}
      </div>
      <Reveal show={open && edge.on}>
        <div className="edgebody">
          <div className="edgegrid">
            <Field label={T('edge_decoy')} hint={T('edge_decoy_hint')}>
              <input value={decoy} onChange={(e) => setDecoy(e.target.value)} dir="ltr" spellCheck={false} />
            </Field>
            <Field label={T('edge_port')}>
              <input value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ''))} dir="ltr" inputMode="numeric" />
            </Field>
          </div>
          <div className="edgewarn">
            <Icon name="warn" />
            <span>{T('edge_decoy_warn')}</span>
          </div>
          <div className="edgeacts">
            <EdgeChip edge={edge} />
            <span className="grow" />
            <button type="button" className="btn" disabled={busy} onClick={() => onSave(edge, decoy.trim().toLowerCase(), Number(port))}>
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
  const [busyId, setBusyId] = useState('')
  const box = useRef(null)
  useRiseIn(box, true)

  const load = async () => {
    const r = await apiPost('cdn-edge', { act: 'state' })
    if (r.ok) {
      setEdges(r.d.edges || [])
    } else {
      postError(r)
      setEdges([])
    }
  }

  useEffect(() => {
    load()
  }, [])

  const toggle = async (edge) => {
    setBusyId(edge.id)
    const r = await apiPost('cdn-edge', { id: edge.id, act: edge.on ? 'off' : 'on' })
    if (r.ok) {
      await load()
      toast(edge.on ? T('edge_toast_off') : T('edge_toast_on'))
    } else {
      postError(r)
    }
    setBusyId('')
  }

  const save = async (edge, decoy, port) => {
    setBusyId(edge.id)
    const r = await apiPost('cdn-edge', { id: edge.id, act: 'on', decoy, port })
    if (r.ok) {
      await load()
      toast(T('edge_toast_saved'))
    } else {
      postError(r)
    }
    setBusyId('')
  }

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
              <EdgeRow key={e.id} edge={e} busy={busyId === e.id} onToggle={toggle} onSave={save} />
            ))}
          </div>
        )}
        {on.length ? <p className="edgecount">{TF('edge_active_count', { n: on.length })}</p> : null}
      </SettingsGroup>
    </div>
  )
}
