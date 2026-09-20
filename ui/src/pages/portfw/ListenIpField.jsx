import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { ipItems } from '../../lib/nodes.js'

export default function ListenIpField({ ips, value, extra, first, onChange }) {
  const items = [{ v: '', label: T('pf_lip_all') }].concat(
    ipItems(extra && !ips.includes(extra) ? ips.concat([extra]) : ips)
  )
  return (
    <>
      <label className={first ? 'first' : undefined}>{T('pf_lip')}</label>
      <Select items={items} value={value} placeholder={T('ip')} onChange={onChange} />
      <div className="muted" style={{ fontSize: 11, margin: '-3px 2px 12px' }}>
        {T(value ? 'pf_lip_note' : 'pf_lip_all_note')}
      </div>
    </>
  )
}
