import { T } from '../i18n/fa.js'

export function GripIcon() {
  return (
    <svg viewBox="0 0 20 20" width="16" height="16" fill="currentColor" aria-hidden="true">
      <circle cx="7" cy="4.5" r="1.5" />
      <circle cx="13" cy="4.5" r="1.5" />
      <circle cx="7" cy="10" r="1.5" />
      <circle cx="13" cy="10" r="1.5" />
      <circle cx="7" cy="15.5" r="1.5" />
      <circle cx="13" cy="15.5" r="1.5" />
    </svg>
  )
}

export default function Grip() {
  return (
    <span className="rgrip" onClick={(e) => e.stopPropagation()} title={T('reord_t')}>
      <GripIcon />
    </span>
  )
}
