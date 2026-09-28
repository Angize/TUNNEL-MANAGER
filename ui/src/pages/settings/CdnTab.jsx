import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import Select from '../../components/Select.jsx'
import SecretInput from '../../components/SecretInput.jsx'
import Reveal from '../../components/Reveal.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import { proxyItems } from '../../components/ProxyFields.jsx'
import { WarnCap } from '../core/form/controls.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { CDN_PROVIDERS, providerName } from '../../lib/cdn.js'
import { T, TF } from '../../i18n/fa.js'

const ICON = { cf: 'globe', ar: 'shield' }

function Chip({ tone, text }) {
  return <span className={'cdnchip ' + tone}>{text}</span>
}

function headChip(status, phase, result) {
  if (phase === 'testing' || phase === 'saving') return <Chip tone="run" text={T('cdn_testing')} />
  if (!status.set) return <Chip tone="off" text={T('cdn_no_key_chip')} />
  if (result && result.error) return <Chip tone="bad" text={T('cdn_chip_err')} />
  if (result && !result.zones) return <Chip tone="warn" text={T('cdn_chip_nozone')} />
  return <Chip tone="ok" text={T('cdn_chip_on')} />
}

function TestResult({ provider, result }) {
  if (result.error) return <WarnCap text={result.error} />
  const checks = result.checks || []
  return (
    <div className="cdnres">
      <div className="cdnresh">
        <Icon name="okc" />
        <b>{TF('cdn_zones_seen', { n: result.zones })}</b>
        <span className="muted">
          {' · '}
          {TF('cdn_zones_usable', { n: result.usable })}
          {' · '}
          {T(result.via === 'proxy' ? 'cdn_via_proxy' : 'cdn_via_direct')}
        </span>
      </div>
      {provider === 'ar' && !result.zones ? <WarnCap text={T('cdn_ar_policy')} /> : null}
      {checks.length ? (
        <div className="cdnperm">
          {checks.map((c) => (
            <div key={c.k} className={'cdnpermr ' + (c.ok ? 'ok' : 'bad')}>
              <Icon name={c.ok ? 'check' : 'x'} />
              <span>{T('cdn_chk_' + c.k)}</span>
              <small>{c.ok ? T('cdn_chk_read') : c.why || T('cdn_chk_no')}</small>
            </div>
          ))}
          <div className="cdnpermn">
            {result.zone ? TF('cdn_chk_zone', { z: result.zone }) + ' · ' : ''}
            {T('cdn_chk_write_later')}
          </div>
        </div>
      ) : null}
      {provider === 'cf' ? <WarnCap tone="gold" text={T('cdn_cf_grpc_note')} /> : null}
    </div>
  )
}

function ProviderCard({ provider, status, proxies, onStatus }) {
  const [phase, setPhase] = useState(status.set ? 'view' : 'edit')
  const [draft, setDraft] = useState('')
  const [result, setResult] = useState(null)

  const test = async () => {
    setPhase('testing')
    const r = await apiPost('cdn-test', { provider })
    setPhase('view')
    setResult(r.ok && r.d.ok ? r.d : { error: postError(r) })
  }

  const save = async () => {
    setPhase('saving')
    const r = await apiPost('cdn-set', { provider, key: draft.trim() })
    if (!(r.ok && r.d.ok)) {
      setPhase('edit')
      setResult({ error: postError(r) })
      return
    }
    setDraft('')
    onStatus(r.d.cdn)
    await test()
  }

  const clear = async () => {
    if (!(await confirmBox(TF('cdn_clear_ask', { p: providerName(provider) }), T('cdn_clear_yes')))) return
    const r = await apiPost('cdn-set', { provider, clear: true })
    if (!(r.ok && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    setResult(null)
    setPhase('edit')
    onStatus(r.d.cdn)
  }

  const route = async (id) => {
    const r = await apiPost('cdn-set', { provider, proxy_id: id === 'direct' ? '' : id })
    if (!(r.ok && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    onStatus(r.d.cdn)
    toast(T('cdn_route_saved'), 'ok')
  }

  const busy = phase === 'testing' || phase === 'saving'
  const editing = phase === 'edit' || phase === 'saving'
  const routes = [{ v: 'direct', label: T('cdn_route_direct'), sub: T('cdn_route_direct_sub') }].concat(
    proxyItems(proxies)
  )

  return (
    <div className="card opc sc-panel apcard cdnprov">
      <div className="ophd">
        <span className={'sgt ' + provider}>
          <Icon name={ICON[provider]} />
        </span>
        <div className="hd2">
          <b>{providerName(provider)}</b>
          <small>{T('cdn_' + provider + '_sub')}</small>
        </div>
        {headChip(status, phase, result)}
      </div>

      <Reveal show={status.set && !editing}>
        <div className="oprow">
          <div className="aptok">
            <Icon name="lock" />
            <span dir="ltr" className="mono tokv">
              {'••••••••••' + (status.tail || '')}
            </span>
          </div>
          <button type="button" className="ghost tone tone-renew opfit" onClick={test} disabled={busy}>
            <Icon name="redo" />
            {T('cdn_test')}
          </button>
          <button type="button" className="ghost opfit" onClick={() => setPhase('edit')} disabled={busy}>
            <Icon name="pen" />
            {T('cdn_change')}
          </button>
          <button
            type="button"
            className="ghost opfit cdnclear"
            onClick={clear}
            disabled={busy || status.used > 0}
            title={T('cdn_clear')}
            aria-label={T('cdn_clear')}
          >
            <Icon name="trash" />
          </button>
        </div>
        {status.used > 0 ? (
          <div className="cdnused">{TF('cdn_used', { n: status.used })}</div>
        ) : null}
      </Reveal>

      <Reveal show={editing}>
        <div>
          <Field label={T('cdn_key_lbl_' + provider)} hint={T('cdn_key_hint_' + provider)}>
            <SecretInput
              value={draft}
              placeholder={T('cdn_key_ph_' + provider)}
              onChange={setDraft}
            />
          </Field>
          <div className="oprow">
            <button type="button" className="primary" disabled={!draft.trim() || busy} onClick={save}>
              {T('cdn_save_test')}
            </button>
            {status.set ? (
              <button type="button" className="ghost opfit" disabled={busy} onClick={() => setPhase('view')}>
                {T('cancel')}
              </button>
            ) : null}
          </div>
        </div>
      </Reveal>

      <Reveal show={!!result && !busy}>
        {result ? <TestResult provider={provider} result={result} /> : null}
      </Reveal>

      <Field label={T('cdn_route_lbl_' + provider)}>
        <Select items={routes} value={status.proxy_id || 'direct'} onChange={route} />
      </Field>
    </div>
  )
}

export default function CdnTab() {
  const [cdn, setCdn] = useState(null)
  const [proxies, setProxies] = useState([])
  const [progress, setProgress] = useState(0)
  const box = useRef(null)

  useRiseIn(box, !!cdn)

  useEffect(() => {
    let alive = true
    apiGet('cdn', setProgress)
      .then((r) => alive && setCdn(r.cdn))
      .catch((e) => alive && toast(readError(e), 'err'))
    apiGet('proxies')
      .then((r) => alive && setProxies(r.proxies || []))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  return (
    <div className="stpage cdnset" ref={box}>
      <LoadBar on={!cdn} value={progress} />
      {cdn
        ? CDN_PROVIDERS.map((p) => (
            <ProviderCard
              key={p}
              provider={p}
              status={cdn[p] || {}}
              proxies={proxies}
              onStatus={setCdn}
            />
          ))
        : null}
      {cdn ? (
        <div className="stnote cdnkeynote">
          <Icon name="lock" />
          <span>{T('cdn_key_note')}</span>
        </div>
      ) : null}
    </div>
  )
}
