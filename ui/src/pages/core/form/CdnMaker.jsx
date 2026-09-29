import { useEffect, useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import Field from '../../../components/Field.jsx'
import Select from '../../../components/Select.jsx'
import Reveal from '../../../components/Reveal.jsx'
import Stepper from '../../../components/Stepper.jsx'
import SwapCascade from '../../../components/SwapCascade.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { CdnSteps } from '../../../components/ActionRow.jsx'
import { apiGet, apiPost } from '../../../lib/api.js'
import { postError, readError } from '../../../lib/errors.js'
import { LTR_TEXT } from '../../../lib/form.js'
import useHeightTween from '../../../lib/useHeightTween.js'
import { CDN_PROVIDERS, labelError, labelOf, providerName, splitZoneKey, zoneItems } from '../../../lib/cdn.js'
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
  if (state === 'names') {
    return (
      <div className="cdncheck ok" role="status">
        <Icon name="okc" />
        <span>
          <b>{T('cdn_is_free')}</b>
          {TF('cdn_names_free', { n: check.hosts.length })}
          <Host h={check.zone} />
          <span className="cdnnames">
            {check.hosts.map((h) => (
              <bdi key={h} className="mono cdnname" dir="ltr">
                {h}
              </bdi>
            ))}
          </span>
        </span>
      </div>
    )
  }
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

function ReadyList({ ready, picked, multi, onPick }) {
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
    <div className="cdnreadyl" role={multi ? 'group' : 'radiogroup'} aria-label={T('cdn_ready_lbl')}>
      {ready.rows.map((r) => {
        const on = picked.includes(r.host)
        return (
          <button
            key={r.host}
            type="button"
            role={multi ? 'checkbox' : 'radio'}
            aria-checked={on}
            className={'cdnreadyr' + (on ? ' on' : '')}
            onClick={() => onPick(r.host)}
          >
            {multi ? (
              <span className={'cdnbox' + (on ? ' on' : '')}>{on ? <Icon name="check" /> : null}</span>
            ) : (
              <span className={'cdnradio' + (on ? ' on' : '')} />
            )}
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

export default function CdnMaker({ form, keys, serverIp, inUse, multi, onPlace, onMade, onClose }) {
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
  const [picked, setPicked] = useState([])
  const [count, setCount] = useState('3')
  const seq = useRef(0)
  const checkBox = useRef(null)
  const newBox = useRef(null)
  const readyBox = useRef(null)
  const first = zones.loading ? null : items.find((it) => !form.Ech || splitZoneKey(it.v).provider === 'cf')
  const zk = key || (first ? first.v : '')
  const { provider, zone } = zk ? splitZoneKey(zk) : { provider: 'cf', zone: '' }
  const echBlocked = !!form.Ech && provider !== 'cf'
  const labelErr = label ? labelError(label) : ''
  const random = !!multi && !label
  const busy = phase === 'checking' || phase === 'making'
  const planned = phase === 'plan' || phase === 'making'
  const checkShown = phase !== 'form' && phase !== 'made'
  const readyKey = ready.error ? 'err' : ready.rows ? 'rows' : 'wait'
  useHeightTween(checkBox, phase === 'checking' ? phase : check, checkShown)
  useHeightTween(readyBox, readyKey, tab === 'ready')

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
    const body = random
      ? { provider, zone, count: Number(count) || 1 }
      : { provider, zone, label, tls: !!form.WsTls, carrier: form.Cdn }
    const r = await apiPost('cdn-check', body)
    if (my !== seq.current) return
    if (!(r.ok && r.d.ok)) {
      setError(postError(r))
      setPhase('form')
      return
    }
    setCheck(random ? { state: 'names', hosts: r.d.hosts || [], zone } : r.d)
    setPhase('plan')
  }

  const build = async (replace) => {
    const labels = check && check.state === 'names' ? check.hosts.map((h) => labelOf(h, zone)) : [label]
    const my = ++seq.current
    setPhase('making')
    setError('')
    setUndone([])
    const r = await apiPost('cdn-make', { provider, zone, labels, replace, ip: serverIp })
    const rows = r.ok && r.d.ok ? r.d.hosts || [] : []
    if (rows.length) onMade(rows)
    if (my !== seq.current) return
    if (!(r.ok && r.d.ok)) {
      setError(postError(r))
      setUndone((r.d && r.d.steps) || [])
      setPhase('plan')
      return
    }
    setMade({ rows, provider, steps: r.d.steps || [] })
    setPhase('made')
  }

  const place = (rows, from) =>
    onPlace(
      rows.map((row) => ({ host: row.host, provider: row.provider, zone: row.zone })),
      from
    )

  const pick = (host) => {
    if (multi) setPicked(picked.includes(host) ? picked.filter((x) => x !== host) : picked.concat(host))
    else setPicked([host])
  }

  const placeWord = (n) => (multi ? (n > 1 ? TF('cdn_place_pool_n', { n }) : T('cdn_place_pool')) : T('cdn_place'))

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
            <div key={readyKey} className="cdnswap">
              <ReadyList ready={ready} picked={picked} multi={multi} onPick={pick} />
            </div>
            {ready.rows && ready.rows.length ? (
              <button
                type="button"
                className="primary cdnact"
                disabled={!picked.length}
                onClick={() => place(ready.rows.filter((r) => picked.includes(r.host)), readyBox.current)}
              >
                <Icon name="check" />
                {placeWord(picked.length)}
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
              <Field label={T(multi ? 'cdn_label_lbl_multi' : 'cdn_label_lbl')} error={labelErr}>
                <div className="cdnlabel">
                  <input
                    {...LTR_TEXT}
                    className="mono"
                    value={label}
                    disabled={phase === 'making'}
                    placeholder={T(multi ? 'cdn_label_ph_multi' : 'cdn_label_ph')}
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
            <Reveal show={random}>
              <div className="cdncount">
                <span>{T('cdn_count_lbl')}</span>
                <Stepper
                  value={count}
                  min={1}
                  max={8}
                  onChange={(v) => {
                    setCount(v)
                    reset()
                  }}
                />
              </div>
            </Reveal>
            {echBlocked ? <WarnCap text={T('cdn_ech_cf_only')} /> : null}
            <Reveal show={checkShown}>
              <div ref={checkBox}>
                <div key={phase === 'checking' ? 'wait' : 'plan'} className="cdnmkb cdnswap">
                  {phase === 'checking' ? (
                    <CheckLine check="checking" provider={provider} />
                  ) : check ? (
                    <>
                      <CheckLine check={check} provider={provider} />
                      {(check.notes || []).map((n) => (
                        <WarnCap key={n.code} tone="gold" text={n.t} />
                      ))}
                    </>
                  ) : null}
                </div>
              </div>
            </Reveal>
            <Reveal show={phase === 'making'}>
              <div className="cdncheck wait" role="status">
                <span className="bspin ink sm" />
                <span>{TF('cdn_making', { p: providerName(provider) })}</span>
              </div>
            </Reveal>
            <Reveal show={phase === 'made'}>
              {made ? (
                <div className="cdnmkb">
                  <CdnSteps steps={made.steps} />
                  <div className="cdndone">
                    <Icon name="okc" />
                    {made.rows.length > 1 ? (
                      <span>{TF('cdn_made_n', { n: made.rows.length, p: providerName(made.provider) })}</span>
                    ) : (
                      <span>
                        <Host h={(made.rows[0] || {}).host} />
                        {TF('cdn_made', { p: providerName(made.provider) })}
                      </span>
                    )}
                  </div>
                </div>
              ) : null}
            </Reveal>
            <Reveal show={undone.length > 0}>
              <CdnSteps steps={undone} />
            </Reveal>
            <Reveal show={!!error}>
              <WarnCap text={error} />
            </Reveal>
            <Reveal show={!(phase === 'plan' && check && check.state === 'tunnel')}>
              {phase === 'made' && made ? (
                <button key="place" type="button" className="primary cdnact" onClick={() => place(made.rows, newBox.current)}>
                  <Icon name="check" />
                  {placeWord(made.rows.length)}
                </button>
              ) : planned && check && check.state === 'ready' ? (
                <button
                  key="take"
                  type="button"
                  className="primary cdnact"
                  onClick={() => place([{ host: check.host, provider, zone }], newBox.current)}
                >
                  <Icon name="check" />
                  {placeWord(1)}
                </button>
              ) : planned && check && (check.state === 'free' || check.state === 'names') ? (
                <button
                  key="make"
                  type="button"
                  className="primary cdnact"
                  disabled={!serverIp || busy}
                  onClick={() => build(false)}
                >
                  <Icon name="plus" />
                  {check.state === 'names' ? TF('cdn_make_n', { n: check.hosts.length }) : T('cdn_make')}
                </button>
              ) : planned && check && check.state === 'manual' ? (
                <button
                  key="replace"
                  type="button"
                  className="primary danger cdnact"
                  disabled={!serverIp || busy}
                  onClick={() => build(true)}
                >
                  <Icon name="redo" />
                  {T('cdn_make_replace')}
                </button>
              ) : planned ? null : (
                <button
                  key="check"
                  type="button"
                  className="ghost tone cdnact"
                  disabled={busy || !zone || (!label && !multi) || !!labelErr || echBlocked}
                  onClick={runCheck}
                >
                  <Icon name="search" />
                  {T('cdn_check_btn')}
                </button>
              )}
            </Reveal>
            <Reveal show={!!(phase === 'plan' && !serverIp && check && check.state !== 'ready' && check.state !== 'tunnel')}>
              <div className="cdnempty">{T('cdn_need_server')}</div>
            </Reveal>
          </div>
        </Reveal>
      </SwapCascade>
    </div>
  )
}
