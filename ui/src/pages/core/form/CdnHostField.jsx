import { useLayoutEffect, useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import { WarnCap } from './controls.jsx'
import CdnMaker from './CdnMaker.jsx'
import ZoneNotes from './ZoneNotes.jsx'
import CleanEdges, { edgeRow } from './CleanEdges.jsx'
import { gsap, reducedMotion } from '../../../lib/motion.js'
import { LTR_TEXT } from '../../../lib/form.js'
import { cdnSingle, edgeFits, edgePort, hasCdnKey, providerName } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

let flyRect = null

function flyFrom(el) {
  flyRect = el ? el.getBoundingClientRect() : null
}

function Placed({ host, provider, onClear }) {
  const box = useRef(null)

  useLayoutEffect(() => {
    const el = box.current
    const from = flyRect
    flyRect = null
    if (!el || !from || reducedMotion()) return
    const to = el.getBoundingClientRect()
    gsap.fromTo(
      el,
      { x: from.left - to.left, y: from.top - to.top, opacity: 0.4 },
      { x: 0, y: 0, opacity: 1, duration: 0.32, ease: 'ease-out', clearProps: 'transform,opacity' }
    )
  }, [])

  return (
    <div className="cdnplaced" ref={box}>
      <span className={'cdnpbadge ' + provider} aria-hidden="true">
        <Icon name={provider === 'ar' ? 'shield' : 'globe'} />
      </span>
      <span className="cdnphost mono" dir="ltr" title={host}>
        {host}
      </span>
      <button type="button" className="cdnpclear" title={T('cdn_unplace_d')} aria-label={T('cdn_unplace')} onClick={onClear}>
        <Icon name="x" />
      </button>
    </div>
  )
}

function PlacedNote({ provider, hostSsl }) {
  return (
    <div className="cdnpnote">
      <span className="cdnpok">
        <Icon name="okc" />
        {TF('cdn_placed_by', { p: providerName(provider) })}
      </span>
      <span className="cdnpdot" aria-hidden="true" />
      <span>{T(hostSsl ? 'cdn_placed_cf' : 'cdn_placed_ar')}</span>
      <span className="cdnpdot" aria-hidden="true" />
      <span>{T(provider === 'ar' ? 'cdn_placed_rule_ar' : 'cdn_placed_rule')}</span>
    </div>
  )
}

function EdgePick({ form, patch, edges, managed }) {
  const tls = !!form.WsTls
  const auto = managed && form.cdnEdgeAuto
  const port = edgePort(form.wsEdge.trim())
  const items = (managed ? [{ v: 'host', label: T('edge_same'), sub: T('edge_same_d') }] : []).concat(
    (edges || []).filter((e) => edgeFits(e, tls)).map(edgeRow)
  )

  return (
    <div className="cdnedge">
      <Field label={T(tls ? 'ws_edge_lbl_wss' : 'ws_edge_lbl')}>
        {auto ? (
          <div className="cdnplaced">
            <span className="cdnpbadge" aria-hidden="true">
              <Icon name="link" />
            </span>
            <span className="cdnsamet">
              <b>{T('edge_same')}</b>
              <span className="mono" dir="ltr">
                {form.wsHost}
              </span>
            </span>
            <button
              type="button"
              className="cdnpclear"
              aria-label={T('edge_same_x')}
              title={T('edge_same_x')}
              onClick={() => patch({ cdnEdgeAuto: false })}
            >
              <Icon name="x" />
            </button>
          </div>
        ) : (
          <div className="cdnsni">
            <input
              {...LTR_TEXT}
              className="mono"
              placeholder={T(tls ? 'cf_edge_ph_tls' : 'cf_edge_ph_plain')}
              value={form.wsEdge}
              onChange={(e) => patch({ wsEdge: e.target.value })}
            />
            <CleanEdges
              items={items}
              value={form.wsEdge.trim()}
              note={T('edge_list_empty')}
              onPick={(v) => patch(v === 'host' ? { cdnEdgeAuto: true } : { cdnEdgeAuto: false, wsEdge: v })}
            />
          </div>
        )}
      </Field>
      {managed && form.cdnOwner === 'cf' && tls && !auto && port && port !== 443 ? (
        <WarnCap tone="gold" text={T('cdn_cf_443')} />
      ) : null}
    </div>
  )
}

export default function CdnHostField({ form, keys, serverIp, patch, onMade }) {
  const [open, setOpen] = useState(false)
  const managed = cdnSingle(form)
  const canMake = hasCdnKey(keys)

  return (
    <div className="cdnhostf">
      <Field label={T('ws_host_lbl')}>
        {managed ? (
          <Placed
            host={form.wsHost}
            provider={form.cdnOwner}
            onClear={() => patch({ wsHost: '', cdnOwner: '', cdnZone: '' })}
          />
        ) : (
          <div className="cdnsni">
            <input
              {...LTR_TEXT}
              placeholder={T('ph_cdn_domain')}
              value={form.wsHost}
              onChange={(e) => patch({ wsHost: e.target.value })}
            />
            {canMake ? (
              <button
                type="button"
                className={'ghost tone tone-renew cdnmake' + (open ? ' on' : '')}
                aria-expanded={open}
                onClick={() => setOpen(!open)}
              >
                <Icon name="globe" />
                {T('cdn_make_open')}
              </button>
            ) : null}
          </div>
        )}
      </Field>
      {managed ? (
        <>
          <PlacedNote
            provider={form.cdnOwner}
            hostSsl={form.cdnOwner === 'cf' && !(keys && keys.cf && keys.cf.ssl_mode === 'zone')}
          />
          <ZoneNotes form={form} zones={[{ provider: form.cdnOwner, zone: form.cdnZone }]} />
        </>
      ) : null}
      <Reveal show={open && !managed}>
        <CdnMaker
          form={form}
          keys={keys}
          serverIp={serverIp}
          inUse={form.wsHost ? [form.wsHost] : []}
          onMade={onMade}
          onClose={() => setOpen(false)}
          onPlace={([row], from) => {
            flyFrom(from)
            patch({ wsHost: row.host, cdnOwner: row.provider, cdnZone: row.zone })
            setOpen(false)
          }}
        />
      </Reveal>
      {managed && form.Ech && form.cdnOwner !== 'cf' ? <WarnCap text={T('cdn_ech_cf_only')} /> : null}
      <EdgePick form={form} patch={patch} edges={keys && keys.edges} managed={managed} />
    </div>
  )
}
