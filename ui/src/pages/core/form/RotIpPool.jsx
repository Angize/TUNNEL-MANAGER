import { Glyph } from '../../../components/Icon.jsx'
import { checkable } from '../../../lib/keys.js'

export default function RotIpPool({ label, ips, selected, onToggle }) {
  const count = ips.filter((ip) => selected[ip]).length

  return (
    <>
      <label className="first">
        {label} <span style={{ color: 'var(--acc-tx)' }}>{'(' + count + ')'}</span>
      </label>
      <div className="rpool" role="group" aria-label={label}>
        {ips.map((ip) => {
          const on = !!selected[ip]
          return (
            <div
              key={ip}
              className={'rrow' + (on ? ' on' : '')}
              {...checkable('checkbox', on, () => onToggle(ip, count))}
            >
              <span className="sic"><Glyph name={on ? 'okc' : 'unchecked'} /></span>
              <span className="rip">{ip}</span>
            </div>
          )
        })}
      </div>
    </>
  )
}
