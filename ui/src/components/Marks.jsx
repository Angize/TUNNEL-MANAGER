const STYLE = { verticalAlign: '-2px', marginInlineStart: '3px' }

const PROPS = {
  width: 12,
  height: 12,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2.6,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  style: STYLE,
}

export function Check() {
  return (
    <svg {...PROPS}>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  )
}

export function Cross() {
  return (
    <svg {...PROPS}>
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  )
}
