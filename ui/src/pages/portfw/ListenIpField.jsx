import Field from '../../components/Field.jsx'
import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { ipItems } from '../../lib/nodes.js'

export default function ListenIpField({ ips, value, extra, first, onChange }) {
  const items = [{ v: '', label: T('pf_lip_all') }].concat(
    ipItems(extra && !ips.includes(extra) ? ips.concat([extra]) : ips)
  )
  return (
    <Field label={T('pf_lip')} hint={T(value ? 'pf_lip_note' : 'pf_lip_all_note')} first={first}>
      <Select items={items} value={value} placeholder={T('ip')} onChange={onChange} />
    </Field>
  )
}
