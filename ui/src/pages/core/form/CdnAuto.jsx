import { useEffect, useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import Field from '../../../components/Field.jsx'
import Select from '../../../components/Select.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import Reveal from '../../../components/Reveal.jsx'
import CopyValue from '../../../components/CopyValue.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { apiGet, apiPost } from '../../../lib/api.js'
import { postError, readError } from '../../../lib/errors.js'
import { alertBox } from '../../../lib/dialog.js'
import { LTR_TEXT } from '../../../lib/form.js'
import { cdnLocked, cdnReady, hostOf, labelError, providerName, sslWord, zoneItems } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

const PLAN_WAIT_MS = 400
const DDOS = { cookie: 'cdn_ddos_cookie', javascript: 'cdn_ddos_js', captcha: 'cdn_ddos_captcha' }

function Step({ tone, title, map, note, chip, children }) {
  const icon = { ok: 'okc', bad: 'xc', new: 'plus' }[tone] || 'warn'
  return (
    <div className={'cdnstep ' + tone}>
      <span className="cdnic">
        <Icon name={icon} />
      </span>
      <span className="cdntx">
        <span className="cdnsth">
          <b>{title}</b>
          {chip ? <span className={'cdnchip ' + (tone === 'new' ? 'run' : tone)}>{chip}</span> : null}
        </span>
        {map ? (
          <code className="cdnmap" dir="ltr">
            {map}
          </code>
        ) : null}
        {note ? <small>{note}</small> : null}
        {children}
      </span>
    </div>
  )
}

function RecordStep({ plan, host, target, form, patch }) {
  const others = (plan.record && plan.record.others) || []
  if (others.length) {
    return (
      <Step tone="warn" title={T('cdn_rec_taken')} map={host + ' → ' + others.join('، ')} note={T('cdn_rec_taken_d')}>
        <Seg2 label={T('cdn_rec_taken')}>
          <SegOpt
            on={form.cdnReplace === true}
            title={T('cdn_rec_replace')}
            sub={T('cdn_rec_replace_d')}
            onClick={() => patch({ cdnReplace: true })}
          />
          <SegOpt
            on={form.cdnReplace === false}
            title={T('cdn_rec_stop')}
            sub={T('cdn_rec_stop_d')}
            onClick={() => patch({ cdnReplace: false })}
          />
        </Seg2>
      </Step>
    )
  }
  if (plan.record && plan.record.mine) {
    return <Step tone="ok" title={T('cdn_rec_mine')} map={host + ' → ' + target} note={T('cdn_rec_mine_d')} chip={T('cdn_ready')} />
  }
  return (
    <Step
      tone="new"
      title={T(plan.provider === 'ar' ? 'cdn_rec_ar' : 'cdn_rec_cf')}
      map={host + ' → ' + target}
      note={T(plan.provider === 'ar' ? 'cdn_rec_ar_d' : 'cdn_rec_cf_d')}
      chip={T('cdn_will_make')}
    />
  )
}

function RedirectStep({ plan, tls }) {
  if (tls || !plan.https_redirect) return null
  return <Step tone="warn" title={T('cdn_redirect_t')} note={T('cdn_redirect_d')} chip={T('cdn_check')} />
}

function CfSteps({ plan, host, port, tls, carrier }) {
  const rules = plan.rules || {}
  const steps = []

  if (plan.ssl) {
    if (plan.ssl === 'flexible' && !plan.ssl_auto) {
      steps.push(<Step key="ssl" tone="ok" title={T('cdn_ssl_ok')} note={T('cdn_ssl_ok_d')} chip={T('cdn_ready')} />)
    } else if (plan.ssl === 'flexible') {
      steps.push(<Step key="ssl" tone="warn" title={T('cdn_ssl_ok')} note={T('cdn_ssl_auto_only')} chip={T('cdn_will_change')} />)
    } else {
      steps.push(
        <Step
          key="ssl"
          tone="warn"
          title={
            <>
              {T('cdn_ssl_t')} <bdi dir="ltr">{sslWord(plan.ssl) + ' → Flexible'}</bdi>
            </>
          }
          note={TF('cdn_ssl_zone', { z: plan.zone, s: sslWord(plan.ssl) }) + (plan.ssl_auto ? ' ' + T('cdn_ssl_auto') : '')}
          chip={T('cdn_will_change')}
        />
      )
    }
  }

  if (rules.mine) {
    steps.push(<Step key="rule" tone="ok" title={T('cdn_rule_mine')} note={T('cdn_rule_mine_d')} chip={T('cdn_ready')} />)
  } else if (rules.join) {
    steps.push(
      <Step key="rule" tone="ok" title={TF('cdn_rule_join', { p: rules.join })} note={T('cdn_rule_join_d')} chip={T('cdn_ready')} />
    )
  } else if (rules.cap && rules.count >= rules.cap) {
    steps.push(
      <Step
        key="rule"
        tone="bad"
        title={T('cdn_rule_full')}
        note={TF('cdn_rule_full_d', { n: rules.count, cap: rules.cap })}
        chip={T('cdn_blocker')}
      />
    )
  } else {
    const manual = (rules.manual || []).length
    steps.push(
      <Step
        key="rule"
        tone="new"
        title={T('cdn_rule_t')}
        map={host + ' → :' + (port || T('cdn_port_free'))}
        note={
          TF('cdn_rule_after', { n: (rules.count || 0) + 1, cap: rules.cap || '—' }) +
          (manual ? ' · ' + TF('cdn_rule_manual', { n: manual }) : '')
        }
        chip={T('cdn_will_make')}
      />
    )
  }

  if (plan.websockets != null) {
    steps.push(
      <Step
        key="ws"
        tone={plan.websockets ? 'ok' : 'new'}
        title="WebSockets"
        note={T(plan.websockets ? 'cdn_on_now' : 'cdn_off_turn_on')}
        chip={T(plan.websockets ? 'cdn_ready' : 'cdn_will_on')}
      />
    )
  }

  if (carrier === 'grpc') {
    steps.push(<Step key="grpc" tone="warn" title="gRPC" note={T('cdn_cf_grpc_step')} chip={T('cdn_manual')} />)
  }

  steps.push(<RedirectStep key="redir" plan={plan} tls={tls} />)
  return steps
}

function ArSteps({ plan, tls, carrier }) {
  const steps = []
  if (plan.https != null) {
    steps.push(
      <Step
        key="https"
        tone={plan.https ? 'ok' : 'new'}
        title={T('cdn_ar_https')}
        note={T(plan.https ? 'cdn_ar_https_on' : 'cdn_ar_https_off')}
        chip={T(plan.https ? 'cdn_ready' : 'cdn_will_on')}
      />
    )
  }
  if (plan.cert === false) {
    steps.push(<Step key="cert" tone="warn" title={T('cdn_ar_cert')} note={T('cdn_ar_cert_d')} chip={T('cdn_check')} />)
  }
  if (plan.ddos === null) {
    steps.push(<Step key="ddos" tone="warn" title={T('cdn_ar_ddos')} note={T('cdn_ar_ddos_unknown')} chip={T('cdn_check')} />)
  } else if (plan.ddos && plan.ddos !== 'off') {
    steps.push(
      <Step
        key="ddos"
        tone="warn"
        title={T('cdn_ar_ddos')}
        note={TF('cdn_ar_ddos_d', { m: DDOS[plan.ddos] ? T(DDOS[plan.ddos]) : plan.ddos })}
        chip={T('cdn_manual')}
      />
    )
  }
  if (carrier === 'grpc') {
    steps.push(
      <Step
        key="grpc"
        tone={plan.grpc ? 'ok' : 'new'}
        title="gRPC"
        note={T(plan.grpc ? 'cdn_on_now' : 'cdn_ar_grpc_on')}
        chip={T('cdn_untested')}
      />
    )
  } else {
    steps.push(<Step key="ws" tone="warn" title="WebSocket" note={T('cdn_ar_ws_d')} chip={T('cdn_untested')} />)
  }
  steps.push(<RedirectStep key="redir" plan={plan} tls={tls} />)
  return steps
}

export function useCdnPlan(form, link) {
  const ready = cdnReady(form)
  const [state, setState] = useState({ plan: null, error: '', loading: false })
  const seq = useRef(0)
  const wantPort = ready && form.cdnMode === 'cf' && form.cdnShare && form.port ? form.port : ''
  const body = useRef(null)
  body.current = ready && {
    provider: form.cdnMode,
    zone: form.cdnZone,
    label: form.cdnLabel,
    carrier: form.Cdn,
    tls: form.WsTls,
    ...(link ? { id: link.id } : {}),
    ...(form.cdnMode === 'cf' ? { share: !!form.cdnShare } : {}),
    ...(wantPort ? { port: wantPort } : {}),
  }
  const key = ready
    ? [form.cdnMode, form.cdnZone, form.cdnLabel, form.Cdn, form.WsTls, form.cdnShare, wantPort].join('|')
    : ''

  useEffect(() => {
    const mine = ++seq.current
    if (!key) {
      setState({ plan: null, error: '', loading: false })
      return undefined
    }
    setState((s) => ({ ...s, loading: true }))
    const timer = setTimeout(async () => {
      const r = await apiPost('cdn-plan', body.current)
      if (mine !== seq.current) return
      if (r.ok && r.d.ok) setState({ plan: r.d, error: '', loading: false })
      else setState({ plan: null, error: postError(r), loading: false })
    }, PLAN_WAIT_MS)
    return () => clearTimeout(timer)
  }, [key])

  return state
}

function useZones(provider, enabled) {
  const [zones, setZones] = useState({})
  const [errors, setErrors] = useState({})

  useEffect(() => {
    if (!enabled || zones[provider]) return undefined
    let alive = true
    apiGet('cdn-zones?provider=' + provider)
      .then((r) => {
        if (!alive) return
        setErrors((e) => ({ ...e, [provider]: '' }))
        setZones((z) => ({ ...z, [provider]: r.zones || [] }))
      })
      .catch((e) => alive && setErrors((x) => ({ ...x, [provider]: readError(e) })))
    return () => {
      alive = false
    }
  }, [provider, enabled, zones])

  return [zones[provider] || null, errors[provider] || '']
}

function Plan({ state, provider, host, target, form, patch, tls }) {
  if (state.error) return <WarnCap text={state.error} />
  if (!state.plan) {
    return state.loading ? (
      <div className="cdnplan">
        <div className="cdnwait">
          <span className="bspin ink sm" />
          {T('cdn_plan_wait')}
        </div>
      </div>
    ) : null
  }
  const plan = state.plan
  return (
    <div className={'cdnplan' + (state.loading ? ' stale' : '')}>
      <div className="cdnph">
        <Icon name="list" />
        <b>{TF('cdn_plan_head', { p: providerName(provider) })}</b>
      </div>
      <RecordStep plan={plan} host={host} target={target} form={form} patch={patch} />
      {provider === 'cf' ? (
        <CfSteps plan={plan} host={host} port={form.port} tls={tls} carrier={form.Cdn} />
      ) : (
        <ArSteps plan={plan} tls={tls} carrier={form.Cdn} />
      )}
    </div>
  )
}

function SharedPorts({ plan, form, patch }) {
  const shared = (plan && plan.rules && plan.rules.shared) || []
  if (!shared.length) return <div className="cdnlock">{T('cdn_share_none')}</div>
  return (
    <div className="cdnports">
      {shared.map((s) => (
        <button
          key={s.port}
          type="button"
          className={'ghost cdnport' + (String(s.port) === String(form.port) ? ' on' : '')}
          title={(s.hosts || []).join('، ')}
          onClick={() => patch({ port: String(s.port), portAuto: false })}
        >
          <span dir="ltr">{s.port}</span>
          <small>{TF('cdn_share_hosts', { n: (s.hosts || []).length })}</small>
        </button>
      ))}
    </div>
  )
}

export default function CdnAuto({ form, keys, serverIp, plan, managed, patch, manual }) {
  const locked = cdnLocked(form)
  const provider = form.cdnMode
  const auto = provider !== 'manual'
  const [zones, zonesError] = useZones(provider, auto && !locked)
  const labelErr = auto ? labelError(form.cdnLabel) : ''
  const zone = (zones || []).find((z) => z.name === form.cdnZone)
  const zoneErr = zone && !zone.ok ? T('cdn_zone_bad') : ''
  const host = hostOf(form.cdnLabel, form.cdnZone)
  const target = (serverIp || '…') + (provider === 'ar' ? ':' + (form.port || T('cdn_port_free')) : '')

  const shown = locked ? 'manual' : provider

  const pick = (p) => {
    if (locked) return
    if (p !== 'manual' && !(keys && keys[p] && keys[p].set)) {
      alertBox(TF('cdn_need_key', { p: providerName(p) }))
      return
    }
    if (p === provider) return
    patch({ cdnMode: p, cdnZone: '', cdnZoneOk: true, cdnReplace: null })
  }

  const sub = (p) => (keys && keys[p] && keys[p].set ? T('cdn_seg_ready') : T('cdn_seg_nokey'))

  return (
    <div className="cdnauto">
      <label>{T('cdn_auto_lbl')}</label>
      <Seg2 label={T('cdn_auto_lbl')}>
        <SegOpt on={shown === 'cf'} title={providerName('cf')} sub={sub('cf')} onClick={() => pick('cf')} />
        <SegOpt on={shown === 'ar'} title={providerName('ar')} sub={sub('ar')} onClick={() => pick('ar')} />
        <SegOpt on={shown === 'manual'} title={T('cdn_manual_opt')} sub={T('cdn_manual_opt_d')} onClick={() => pick('manual')} />
      </Seg2>
      {locked ? <div className="cdnlock">{T('cdn_locked')}</div> : null}

      <Reveal show={auto && !locked}>
        <div>
          <div className="cdngrid">
            <Field label={T('cdn_zone_lbl')} error={zonesError || zoneErr}>
              <Select
                items={zoneItems(provider, zones)}
                value={form.cdnZone}
                placeholder={T(zones || zonesError ? 'cdn_zone_pick' : 'cdn_zone_loading')}
                onChange={(v) => {
                  const picked = (zones || []).find((z) => z.name === v)
                  patch({ cdnZone: v, cdnZoneOk: !picked || !!picked.ok, cdnReplace: null })
                }}
              />
            </Field>
            <Field label={T('cdn_label_lbl')} error={form.cdnLabel && labelErr ? labelErr : ''}>
              <div className="cdnlabel">
                <input
                  {...LTR_TEXT}
                  className="mono"
                  value={form.cdnLabel}
                  placeholder={T('cdn_label_ph')}
                  onChange={(e) => patch({ cdnLabel: e.target.value.toLowerCase().trim(), cdnReplace: null })}
                />
                <span className="cdnsuffix" dir="ltr">
                  {'.' + (form.cdnZone || '…')}
                </span>
              </div>
            </Field>
          </div>
          <div className="cdnhost">
            <span className="muted">{T('cdn_host_lbl')}</span>
            <CopyValue text={host} />
          </div>
          <SwitchRow
            on={form.cdnEdgeAuto}
            title={T('cdn_edge_auto_t')}
            note={T('cdn_edge_auto_d')}
            onToggle={() => patch({ cdnEdgeAuto: !form.cdnEdgeAuto })}
          />
          <Reveal show={!form.cdnEdgeAuto}>
            <Field label={T(form.WsTls ? 'ws_edge_lbl_wss' : 'ws_edge_lbl')}>
              <input
                {...LTR_TEXT}
                className="mono"
                placeholder={T(form.WsTls ? 'cf_edge_ph_tls' : 'cf_edge_ph_plain')}
                value={form.wsEdge}
                onChange={(e) => patch({ wsEdge: e.target.value })}
              />
            </Field>
          </Reveal>
          {provider === 'cf' && form.WsTls ? <WarnCap tone="gold" text={T('cdn_cf_443')} /> : null}
          <Reveal show={provider === 'cf'}>
            <div>
              <SwitchRow
                on={!!form.cdnShare}
                title={T('cdn_share_t')}
                note={T('cdn_share_d')}
                onToggle={() => patch({ cdnShare: !form.cdnShare })}
              />
              <Reveal show={!!form.cdnShare}>
                <SharedPorts plan={plan.plan} form={form} patch={patch} />
              </Reveal>
            </div>
          </Reveal>
          <Plan
            state={plan}
            provider={provider}
            host={host}
            target={target}
            form={form}
            patch={patch}
            tls={form.WsTls}
          />
        </div>
      </Reveal>

      <Reveal show={!auto || locked}>
        <div>
          {managed ? (
            <SwitchRow
              on={form.cdnKeep}
              title={T('cdn_keep_t')}
              note={T('cdn_keep_edit_d')}
              onToggle={() => patch({ cdnKeep: !form.cdnKeep })}
            />
          ) : null}
          {manual}
        </div>
      </Reveal>
    </div>
  )
}
