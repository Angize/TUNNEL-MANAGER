import Field from './Field.jsx'
import Select from './Select.jsx'
import { T } from '../i18n/fa.js'
import { ipItems } from '../lib/nodes.js'
import './ipfield.css'

export default function IpField({ label, ips, value, onChange }) {
  return (
    <Field label={label} first>
      {ips.length > 1 ? (
        <Select items={ipItems(ips)} value={value} placeholder={T('ip')} onChange={onChange} />
      ) : (
        <input className="mono ipro" value={ips[0] || '—'} readOnly />
      )}
    </Field>
  )
}
