import { useEffect } from 'react'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import Field from '../../../components/Field.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import Stepper from '../../../components/Stepper.jsx'
import Select from '../../../components/Select.jsx'
import { proxyItems } from '../../../components/ProxyFields.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { wssMandatory } from './gates.js'
import { sniModes } from './presets.js'
import { limitErr } from './validate.js'
import { alertBox } from '../../../lib/dialog.js'
import { T } from '../../../i18n/fa.js'

function EchProxyPicker({ proxies, value, patch, ...aria }) {
  const first = proxies.length ? proxies[0].id : ''

  useEffect(() => {
    if (!value && first) patch({ echProxyId: first })
  }, [value, first, patch])

  if (!proxies.length) {
    return (
      <div className="muted" style={{ fontSize: 12 }}>
        {T('nd_proxy_none')}
      </div>
    )
  }
  return (
    <Select
      {...aria}
      items={proxyItems(proxies)}
      value={value}
      placeholder={T('select')}
      onChange={(v) => patch({ echProxyId: v })}
    />
  )
}

function Toggles({ form, cfg, proxies, patch }) {
  const locked = wssMandatory(form, form.pool)

  const toggleTls = () => {
    if (form.WsTls) patch({ WsTls: false, Ech: false, SniSplit: false })
    else patch({ WsTls: true })
  }

  const toggleEch = () => {
    if (!form.WsTls) {
      patch({ Ech: false })
      alertBox(T('ech_need_wss_alert'))
      return
    }
    patch({ Ech: !form.Ech })
  }

  const toggleSni = () => {
    if (!form.WsTls) {
      patch({ SniSplit: false })
      alertBox(T('sni_need_wss'))
      return
    }
    patch({ SniSplit: !form.SniSplit })
  }

  return (
    <>
      <SwitchRow
        on={form.WsTls}
        title={T('wstls_t')}
        note={T('wstls_d')}
        locked={locked}
        onToggle={toggleTls}
      />
      <SwitchRow on={form.Ech} title={T('ech_t')} note={T('ech_d')} onToggle={toggleEch} />
      <Reveal show={!!form.Ech}>
        <>
          <SwitchRow
            on={form.EchProxy}
            title={T('echpx_t')}
            note={T('echpx_d')}
            onToggle={() => patch({ EchProxy: !form.EchProxy })}
          />
          <Reveal show={!!form.EchProxy}>
            <Field label={T('nd_proxy_pick')} style={{ marginTop: 8 }}>
              <EchProxyPicker proxies={proxies} value={form.echProxyId} patch={patch} />
            </Field>
          </Reveal>
        </>
      </Reveal>
      <SwitchRow on={form.SniSplit} title={T('sni_t')} note={T('sni_d')} onToggle={toggleSni} />
      <Reveal show={!!form.SniSplit}>
        <div style={{ marginTop: 8 }}>
          <Field label={T('sni_pos_lbl')}>
            <NumberInput value={form.splitPos} onChange={(v) => patch({ splitPos: v })} />
            <WarnCap text={limitErr(form, 'splitPos', cfg.limits)} style={{ marginTop: 8 }} />
          </Field>
          <label style={{ marginTop: 10, display: 'block' }}>{T('sni_mode_lbl')}</label>
          <Seg2 label={T('sni_mode_lbl')}>
            {sniModes().map((mode) => (
              <SegOpt
                key={mode.v}
                on={mode.v === form.SniMode}
                title={mode.t}
                sub={mode.s}
                onClick={() => patch({ SniMode: mode.v })}
              />
            ))}
          </Seg2>
          <Reveal show={form.SniMode === 'disorder'}>
            <Field label={T('sni_ttl_lbl')} style={{ marginTop: 8 }}>
              <Stepper
                min={cfg.limits.split_ttl[0]}
                max={cfg.limits.split_ttl[1]}
                value={form.splitTtl}
                onChange={(v) => patch({ splitTtl: v })}
              />
              <WarnCap text={limitErr(form, 'splitTtl', cfg.limits)} style={{ marginTop: 8 }} />
            </Field>
          </Reveal>
        </div>
      </Reveal>
    </>
  )
}

export default function WsToggleRows(props) {
  return (
    <Reveal show={props.form.Tr === 'ws'}>
      <Toggles {...props} />
    </Reveal>
  )
}
