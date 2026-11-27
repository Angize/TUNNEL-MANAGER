import { Glyph } from './Icon.jsx'

const STYLE = { verticalAlign: '-2px', marginInlineStart: '3px' }

export function Check() {
  return <Glyph name="check" width={12} height={12} strokeWidth={2.6} style={STYLE} />
}

export function Cross() {
  return <Glyph name="x" width={12} height={12} strokeWidth={2.6} style={STYLE} />
}
