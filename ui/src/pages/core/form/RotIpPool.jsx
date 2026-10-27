import { checkable } from '../../../lib/keys.js'

const CHECKED = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
    <circle cx="12" cy="12" r="9" />
    <path d="M8.3 12.4l2.6 2.6 4.8-5.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
)

const EMPTY = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="9" />
  </svg>
)

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
              <span className="sic">{on ? CHECKED : EMPTY}</span>
              <span className="rip">{ip}</span>
            </div>
          )
        })}
      </div>
    </>
  )
}
