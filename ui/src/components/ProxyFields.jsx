import { useEffect } from 'react'
import Field from './Field.jsx'
import Select from './Select.jsx'
import { T } from '../i18n/fa.js'
import SwitchRow from './SwitchRow.jsx'
import Reveal from './Reveal.jsx'

export function proxyItems(proxies) {
  return (proxies || []).map((p) => ({ v: p.id, label: p.name, sub: p.addr }))
}


export default function ProxyFields({ proxies, value, onChange }) {
  const items = proxyItems(proxies)
  const selected = value.id || (items.length ? items[0].v : '')
  const toggle = () => onChange({ on: !value.on, id: selected })

  useEffect(() => {
    if (value.on && !value.id && selected) onChange({ on: true, id: selected })
  }, [value.on, value.id, selected, onChange])

  return (
    <>
      <SwitchRow on={value.on} title={T('nd_proxy_on')} note={T('nd_proxy_all')} onToggle={toggle} />
      <Reveal show={value.on}>
        {items.length ? (
          <Field label={T('nd_proxy_pick')}>
            <Select items={items} value={selected} onChange={(pid) => onChange({ on: true, id: pid })} />
          </Field>
        ) : (
          <div className="muted" style={{ fontSize: 12, margin: '12px 2px 0' }}>
            {T('nd_proxy_none')}
          </div>
        )}
      </Reveal>
    </>
  )
}

export function proxyBody(value) {
  return { proxy_on: !!value.on, proxy_id: value.on ? value.id || '' : '' }
}
