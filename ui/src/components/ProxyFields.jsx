import { useEffect } from 'react'
import Select from './Select.jsx'
import { T } from '../i18n/fa.js'
import { checkable } from '../lib/keys.js'

export default function ProxyFields({ proxies, value, onChange }) {
  const items = (proxies || []).map((p) => ({ v: p.id, label: p.name, sub: p.addr }))
  const selected = value.id || (items.length ? items[0].v : '')

  useEffect(() => {
    if (value.on && !value.id && selected) onChange({ on: true, id: selected })
  }, [value.on, value.id, selected, onChange])

  return (
    <>
      <div className="tglbox">
        <div
          className={'tglsw' + (value.on ? ' on' : '')}
          {...checkable('switch', value.on, () => onChange({ on: !value.on, id: selected }))}
        />
        <div className="tt">
          <b>{T('nd_proxy_on')}</b>
          <small>{T('nd_proxy_all')}</small>
        </div>
      </div>
      {value.on ? (
        <div>
          <label>{T('nd_proxy_pick')}</label>
          {items.length ? (
            <Select items={items} value={selected} onChange={(id) => onChange({ on: true, id })} />
          ) : (
            <div className="muted" style={{ fontSize: 12 }}>
              {T('nd_proxy_none')}
            </div>
          )}
        </div>
      ) : null}
    </>
  )
}

export function proxyBody(value) {
  return { proxy_on: !!value.on, proxy_id: value.on ? value.id || '' : '' }
}
