import { useEffect } from 'react'
import Select from '../../../components/Select.jsx'
import { Seg2, SegOpt, TglBox } from './controls.jsx'
import { wssMandatory } from './gates.js'
import { sniModes } from './presets.js'
import { alertBox } from '../../../lib/dialog.js'
import { T } from '../../../i18n/fa.js'

function EchProxyPicker({ proxies, value, patch }) {
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
  const items = proxies.map((p) => ({ v: p.id, label: p.name, sub: p.addr }))
  return (
    <Select
      items={items}
      value={value}
      placeholder={T('select')}
      onChange={(v) => patch({ echProxyId: v })}
    />
  )
}

export default function WsToggleRows({ form, cfg, proxies, patch }) {
  if (form.Tr !== 'ws') return null
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
      <TglBox
        on={form.WsTls}
        title={T('wstls_t')}
        note={T('wstls_d')}
        locked={locked}
        gap={10}
        onClick={toggleTls}
      />
      <TglBox on={form.Ech} title={T('ech_t')} note={T('ech_d')} gap={9} onClick={toggleEch} />
      {form.Ech ? (
        <>
          <TglBox
            on={form.EchProxy}
            title={T('echpx_t')}
            note={T('echpx_d')}
            gap={9}
            onClick={() => patch({ EchProxy: !form.EchProxy })}
          />
          {form.EchProxy ? (
            <div style={{ marginTop: 6 }}>
              <label>{T('nd_proxy_pick')}</label>
              <EchProxyPicker proxies={proxies} value={form.echProxyId} patch={patch} />
            </div>
          ) : null}
        </>
      ) : null}
      <TglBox on={form.SniSplit} title={T('sni_t')} note={T('sni_d')} gap={9} onClick={toggleSni} />
      {form.SniSplit ? (
        <div style={{ marginTop: 6 }}>
          <div>
            <label>{T('sni_pos_lbl')}</label>
            <input
              type="number"
              min={0}
              max={1400}
              value={form.splitPos}
              onChange={(e) => patch({ splitPos: e.target.value })}
            />
          </div>
          <label style={{ marginTop: 10, display: 'block' }}>{T('sni_mode_lbl')}</label>
          <Seg2>
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
          {form.SniMode === 'disorder' ? (
            <div style={{ marginTop: 6 }}>
              <label>{T('sni_ttl_lbl')}</label>
              <input
                type="number"
                min={0}
                max={cfg.split_ttl_max}
                value={form.splitTtl}
                onChange={(e) => patch({ splitTtl: e.target.value })}
              />
            </div>
          ) : null}
        </div>
      ) : null}
    </>
  )
}
