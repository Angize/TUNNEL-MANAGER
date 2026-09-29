import { useEffect, useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import Field from '../../../components/Field.jsx'
import Select from '../../../components/Select.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwapCascade from '../../../components/SwapCascade.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { CdnSteps } from '../../../components/ActionRow.jsx'
import { apiGet, apiPost } from '../../../lib/api.js'
import { postError, readError } from '../../../lib/errors.js'
import { LTR_TEXT } from '../../../lib/form.js'
import { CDN_PROVIDERS, labelError, providerName, splitZoneKey, zoneItems } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

function useZones(keys) {
  const [by, setBy] = useState({})
  const [errs, setErrs] = useState({})
  const wanted = CDN_PROVIDERS.filter((p) => keys && keys[p] && keys[p].set)
  const sig = wanted.join(',')

  useEffect(() => {
    let alive = true
    for (const p of sig ? sig.split(',') : []) {
      apiGet('cdn-zones?provider=' + p)
        .then((r) => alive && setBy((x) => ({ ...x, [p]: r.zones || [] })))
        .catch((e) => alive && setErrs((x) => ({ ...x, [p]: TF('cdn_zones_failed', { p: providerName(p), e: readError(e) }) })))
    }
    return () => {
      alive = false
    }
  }, [sig])

  return {
    by,
    error: wanted.map((p) => errs[p]).filter(Boolean).join(' '),
    loading: wanted.some((p) => !by[p] && !errs[p]),
  }
}

function useReady(inUse) {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    apiGet('cdn')
      .then((r) => alive && setRows(((r.cdn && r.cdn.hosts) || []).filter((h) => !h.link)))
      .catch((e) => alive && setError(readError(e)))
    return () => {
      alive = false
    }
  }, [])

  return { rows: rows && rows.filter((r) => !inUse.includes(r.host)), error }
}

function Host({ h }) {
  return (
    <bdi className="mono cdnhostv" dir="ltr">
      {h}
    </bdi>
  )
}

function CheckLine({ check, provider }) {
  if (check === 'checking') {
    return (
      <div className="cdncheck wait" role="status">
        <span className="bspin ink sm" />
        <span>{TF('cdn_checking', { p: providerName(provider) })}</span>
      </div>
    )
  }
  const { state, host } = check
  if (state === 'tunnel') {
    return (
      <div className="cdncheck bad" role="status">
        <Icon name="xc" />
        <span>
          <b>{T('cdn_taken')}</b>
          {' — '}
          <Host h={host} />
          {TF('cdn_taken_tunnel', { n: check.tunnel || '?' })}
        </span>
      </div>
    )
  }
  if (state === 'manual') {
    return (
      <div className="cdncheck warn" role="status">
        <Icon name="warn" />
        <span>
          <b>{T('cdn_taken')}</b>
          {' — '}
          <Host h={host} />
          {T('cdn_taken_manual')}
          {(check.records || []).map((r) => (
            <code key={r} className="mono cdnrec" dir="ltr">
              {r}
            </code>
          ))}
        </span>
      </div>
    )
  }
  if (state === 'ready') {
    return (
      <div className="cdncheck ok" role="status">
        <Icon name="okc" />
        <span>
          <b>{T('cdn_is_ready')}</b>
          {' — '}
          <Host h={host} />
          {T('cdn_is_ready_d')}
        </span>
      </div>
    )
  }
  return (
    <div className="cdncheck ok" role="status">
      <Icon name="okc" />
      <span>
        <b>{T('cdn_is_free')}</b>
        {' — '}
        <Host h={host} />
        {T('cdn_is_free_d')}
      </span>
    </div>
  )
}

function ReadyList({ ready, picked, onPick }) {
  if (ready.error) return <WarnCap text={ready.error} />
  if (!ready.rows) {
    return (
      <div className="cdncheck wait">
        <span className="bspin ink sm" />
        <span>{T('cdn_ready_loading')}</span>
      </div>
    )
  }
  if (!ready.rows.length) return <div className="cdnempty">{T('cdn_ready_none')}</div>
  return (
    <div className="cdnreadyl" role="radiogroup" aria-label={T('cdn_ready_lbl')}>
      {ready.rows.map((r) => {
        const on = picked === r.host
        return (
          <button
            key={r.host}
            type="button"
            role="radio"
            aria-checked={on}
            className={'cdnreadyr' + (on ? ' on' : '')}
            onClick={() => onPick(r.host)}
          >
            <span className={'cdnradio' + (on ? ' on' : '')} />
            <span className="mono" dir="ltr">
              {r.host}
            </span>
            <span className="cdnmeta">{providerName(r.provider)}</span>
          </button>
        )
      })}
    </div>
  )
}

export default function CdnMaker({ form, keys, serverIp, inUse, onPlace, onMade, onClose }) {
  const zones = useZones(keys)
  const ready = useReady(inUse)
  const items = zoneItems(zones.by, !!form.Ech)
  const [tab, setTab] = useState('new')
  const [key, setKey] = useState('')
  const [label, setLabel] = useState('')
  const [phase, setPhase] = useState('form')
  const [check, setCheck] = useState(null)
  const [made, setMade] = useState(null)
  const [error, setError] = useState('')
  const [undone, setUndone] = useState([])
  const [picked, setPicked] = useState('')
  const seq = useRef(0)
  const newBox = useRef(null)
  const readyBox = useRef(null)
  const first = zones.loading ? null : items.find((it) => !form.Ech || splitZoneKey(it.v).provider === 'cf')
  const zk = key || (first ? first.v : '')
  const { provider, zone } = zk ? splitZoneKey(zk) : { provider: 'cf', zone: '' }
  const echBlocked = !!form.Ech && provider !== 'cf'
  const labelErr = label ? labelError(label) : ''
  const busy = phase === 'checking' || phase === 'making'

  const reset = () => {
    seq.current++
    setPhase('form')
    setCheck(null)
    setError('')
    setUndone([])
  }

  const runCheck = async () => {
    const my = ++seq.current
    setPhase('checking')
    setError('')
    const r = await apiPost('cdn-check', { provider, zone, label, tls: !!form.WsTls, carrier: form.Cdn })
    if (my !== seq.current) return
    if (!(r.ok && r.d.ok)) {
      setError(postError(r))
      setPhase('form')
      return
    }
    setCheck(r.d)
    setPhase('plan')
  }

  const build = async (replace) => {
    const my = ++seq.current
    setPhase('making')
    setError('')
    setUndone([])
    const r = await apiPost('cdn-make', { provider, zone, labels: [label], replace, ip: serverIp })
    const rows = r.ok && r.d.ok ? r.d.hosts || [] : []
    if (rows.length) onMade(rows)
    if (my !== seq.current) return
    if (!(r.ok && r.d.ok)) {
      setError(postError(r))
      setUndone((r.d && r.d.steps) || [])
      setPhase('plan')
      return
    }
    setMade({ ...(rows[0] || { host: label + '.' + zone, provider, zone }), steps: r.d.steps || [] })
    setPhase('made')
  }

  const place = (row, from) => onPlace({ host: row.host, provider: row.provider, zone: row.zone }, from)

  const readyCount = ready.rows ? ready.rows.length : 0

  return (
    <div className="card cdnmk">
      <div className="cdnmkh">
        <Icon name="globe" />
        <b>{T('cdn_mk_t')}</b>
        <button type="button" className="ghost cdnx" aria-label={T('close')} onClick={onClose}>
          <Icon name="x" />
        </button>
      </div>
      <Seg2 label={T('cdn_mk_src')}>
        <SegOpt on={tab === 'new'} title={T('cdn_mk_new')} sub={T('cdn_mk_new_d')} onClick={() => setTab('new')} />
        <SegOpt
          on={tab === 'ready'}
          title={ready.rows ? TF('cdn_mk_ready_n', { n: readyCount }) : T('cdn_mk_ready')}
          sub={T('cdn_mk_ready_d')}
          onClick={() => setTab('ready')}
        />
      </Seg2>
      <SwapCascade value={tab}>
        <Reveal show={tab === 'ready'}>
          <div className="cdnmkb" ref={readyBox}>
            <ReadyList ready={ready} picked={picked} onPick={setPicked} />
            {ready.rows && ready.rows.length ? (
              <button
                type="button"
                className="primary cdnact"
                disabled={!picked}
                onClick={() => place(ready.rows.find((r) => r.host === picked), readyBox.current)}
              >
                <Icon name="check" />
                {T('cdn_place')}
              </button>
            ) : null}
          </div>
        </Reveal>
        <Reveal show={tab === 'new'}>
          <div className="cdnmkb" ref={newBox}>
            {zones.error ? <WarnCap text={zones.error} /> : null}
            <div className="cdngrid cdnmkgrid">
              <Field label={T('cdn_zone_lbl')}>
                <Select
                  items={items}
                  value={zk}
                  placeholder={T(zones.loading ? 'cdn_zone_loading' : 'cdn_zone_pick')}
                  onChange={(v) => {
                    setKey(v)
                    reset()
                  }}
                />
              </Field>
              <Field label={T('cdn_label_lbl')} error={labelErr}>
                <div className="cdnlabel">
                  <input
                    {...LTR_TEXT}
                    className="mono"
                    value={label}
                    disabled={phase === 'making'}
                    placeholder={T('cdn_label_ph')}
                    onChange={(e) => {
                      setLabel(e.target.value.toLowerCase().trim())
                      reset()
                    }}
                  />
                  <span className="cdnsuffix" dir="ltr">
                    {'.' + (zone || '…')}
                  </span>
                </div>
              </Field>
            </div>
            {echBlocked ? <WarnCap text={T('cdn_ech_cf_only')} /> : null}
            <Reveal show={phase !== 'form' && phase !== 'made'}>
              {phase === 'checking' ? (
                <CheckLine check="checking" provider={provider} />
              ) : check ? (
                <div className="cdnmkb">
                  <CheckLine check={check} provider={provider} />
                  {(check.notes || []).map((n) => (
                    <WarnCap key={n.code} tone="gold" text={n.t} />
                  ))}
                </div>
              ) : null}
            </Reveal>
            {phase === 'making' ? (
              <div className="cdncheck wait" role="status">
                <span className="bspin ink sm" />
                <span>{TF('cdn_making', { p: providerName(provider) })}</span>
              </div>
            ) : null}
            <Reveal show={phase === 'made'}>
              {made ? (
                <div className="cdnmkb">
                  <CdnSteps steps={made.steps} />
                  <div className="cdndone">
                    <Icon name="okc" />
                    <span>
                      <Host h={made.host} />
                      {TF('cdn_made', { p: providerName(made.provider) })}
                    </span>
                  </div>
                </div>
              ) : null}
            </Reveal>
            <CdnSteps steps={undone} />
            {error ? <WarnCap text={error} /> : null}
            {phase === 'made' && made ? (
              <button type="button" className="primary cdnact" onClick={() => place(made, newBox.current)}>
                <Icon name="check" />
                {T('cdn_place')}
              </button>
            ) : phase === 'plan' && check && check.state === 'ready' ? (
              <button
                type="button"
                className="primary cdnact"
                onClick={() => place({ host: check.host, provider, zone }, newBox.current)}
              >
                <Icon name="check" />
                {T('cdn_place')}
              </button>
            ) : phase === 'plan' && check && check.state === 'free' ? (
              <button type="button" className="primary cdnact" disabled={!serverIp} onClick={() => build(false)}>
                <Icon name="plus" />
                {T('cdn_make')}
              </button>
            ) : phase === 'plan' && check && check.state === 'manual' ? (
              <button type="button" className="primary danger cdnact" disabled={!serverIp} onClick={() => build(true)}>
                <Icon name="redo" />
                {T('cdn_make_replace')}
              </button>
            ) : phase === 'plan' ? null : (
              <button
                type="button"
                className="ghost tone cdnact"
                disabled={busy || !zone || !label || !!labelErr || echBlocked}
                onClick={runCheck}
              >
                <Icon name="search" />
                {T('cdn_check_btn')}
              </button>
            )}
            {phase === 'plan' && !serverIp && check && check.state !== 'ready' && check.state !== 'tunnel' ? (
              <div className="cdnempty">{T('cdn_need_server')}</div>
            ) : null}
          </div>
        </Reveal>
      </SwapCascade>
    </div>
  )
}
