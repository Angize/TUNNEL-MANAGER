import { Glyph } from './Icon.jsx'
import { T } from '../i18n/fa.js'

export function GripIcon() {
  return <Glyph name="grip" width={16} height={16} strokeWidth={2.8} />
}

export default function Grip() {
  return (
    <span className="rgrip" onClick={(e) => e.stopPropagation()} title={T('reord_t')}>
      <GripIcon />
    </span>
  )
}
