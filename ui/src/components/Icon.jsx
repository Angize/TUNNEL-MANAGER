export const CHECK_PATH = 'm4.5 12.5 4.8 4.7L19.5 6.8'

const TUNNEL = (
  <>
    <rect x="2" y="9" width="4" height="6" rx="1" />
    <rect x="18" y="9" width="4" height="6" rx="1" />
    <path d="M6 12h12M7.5 8.1 9 6.5h6l1.5 1.6m-9 7.8L9 17.5h6l1.5-1.6" />
    <rect x="10" y="10" width="4" height="4" rx=".7" fill="currentColor" stroke="none" />
  </>
)

const PATHS = {
  shield: (
    <>
      <path d="M12 2.8 20 6v5.5c0 4.7-3.1 7.7-8 10-4.9-2.3-8-5.3-8-10V6z" />
      <path d="M7.5 12h2.3l1.5-3.2 2 6 1.6-3H17" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10" width="15" height="11" rx="2.6" />
      <path d="M8 10V7.5a4 4 0 0 1 8 0V10m-4 5v2" />
    </>
  ),
  dash: (
    <>
      <rect x="3" y="3.5" width="18" height="17" rx="3" />
      <path d="M3 9h18M7 16l3-3 3 2 4-4" />
    </>
  ),
  server: (
    <>
      <rect x="4" y="3" width="16" height="7" rx="1.8" />
      <rect x="4" y="14" width="16" height="7" rx="1.8" />
      <path d="M7.5 6.5h.5m-.5 11h.5M15 6.5h2m-2 11h2M8 10v4m8-4v4" />
    </>
  ),
  nodeTransfer: (
    <>
      <rect x="10" y="3" width="12" height="6" rx="1.7" />
      <rect x="2" y="15" width="12" height="6" rx="1.7" />
      <path d="M13 6h.4M5 18h.4M7 6H6a2 2 0 0 0-2 2v4m-2.2-2.2L4 12l2.2-2.2" />
    </>
  ),
  link: TUNNEL,
  globe: (
    <>
      <circle cx="12" cy="12" r="8.8" />
      <path d="M3.4 10h17.2M12 3.2c-3.7 4-4.6 12.7 0 17.6m0-17.6c2.6 2.7 3.8 6.5 3.5 10.2M5.4 16H16" />
    </>
  ),
  list: (
    <>
      <rect x="4" y="3" width="16" height="18" rx="2.4" />
      <path d="M7.4 7.4h.3m2.8 0h6m-9.1 4.6h.3m2.8 0h6m-9.1 4.6h.3m2.8 0H15" />
    </>
  ),
  cpu: (
    <>
      <rect x="5.8" y="5.8" width="12.4" height="12.4" rx="2" />
      <rect x="9.4" y="9.4" width="5.2" height="5.2" rx="1" />
      <path d="M9 2.5v3m6-3v3m-6 13v3m6-3v3M2.5 9h3m-3 6h3m13-6h3m-3 6h3" />
    </>
  ),
  cog: (
    <>
      <path d="M5 6h7m4 0h3M5 12h2m4 0h8M5 18h9m4 0h1" />
      <circle cx="14" cy="6" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="16" cy="18" r="2" />
    </>
  ),
  logout: <path d="M12 4h6a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-6m0-8H3m4-4-4 4 4 4" />,
  moon: (
    <>
      <path d="M18.5 15.7A8 8 0 0 1 8.3 5.5 8.2 8.2 0 1 0 18.5 15.7Z" />
      <path d="m16 3 .7 2.2L19 6l-2.3.8L16 9l-.7-2.2L13 6l2.3-.8Z" />
    </>
  ),
  activity: <path d="M2.5 12h4.1l2.2-6.3 4.1 13 2.8-8.2 1.6 1.5h4.2" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="8.6" />
      <path d="M12 6v6l4 2.4M5.5 6.5l1 1" />
    </>
  ),
  traf: <path d="M3.5 20V8.5L6 6m-2.5 2.5L1.5 7m8 12.5v-7m5 7v-11M20 4v11l2.4-2.5M20 15l-2.4-2.5" />,
  grid: (
    <>
      <rect x="3.4" y="3.4" width="6.7" height="6.7" rx="1.7" />
      <rect x="14" y="3.4" width="6.7" height="6.7" rx="1.7" />
      <rect x="3.4" y="14" width="6.7" height="6.7" rx="1.7" />
      <rect x="14" y="14" width="6.7" height="6.7" rx="1.7" />
    </>
  ),
  redo: <path d="M19.5 8.7A8 8 0 1 0 20 14m-.4-10v5.3h-5.3" />,
  warn: (
    <>
      <path d="M10.4 4.6a1.8 1.8 0 0 1 3.2 0l7.1 13.5a1.5 1.5 0 0 1-1.3 2.2H4.6a1.5 1.5 0 0 1-1.3-2.2z" />
      <path d="M12 9v4.1m0 3.2v.25" />
    </>
  ),
  search: (
    <>
      <circle cx="10" cy="10" r="6.3" />
      <path d="M14.7 14.7l5.5 5.5M7.2 9.7a2.8 2.8 0 0 1 2.5-2.5" />
    </>
  ),
  chev: <path d="M5.8 9.2 11 14.4a1.4 1.4 0 0 0 2 0l5.2-5.2" />,
  cloud: <path d="M6.8 18.5a4.3 4.3 0 0 1-1.1-8.4A6.5 6.5 0 0 1 18 8.9a4.9 4.9 0 0 1 .1 9.6z" />,
  restart: <path d="M12 3v8.5m-4-6a8 8 0 1 0 10.3 2M19.7 4.7v4.1h-4" />,
  pause: (
    <>
      <rect x="5" y="4.5" width="4.3" height="15" rx="1.2" />
      <rect x="14.7" y="4.5" width="4.3" height="15" rx="1.2" />
    </>
  ),
  play: <path d="M7 5.3a1.1 1.1 0 0 1 1.7-.9l10.5 6.7a1 1 0 0 1 0 1.8L8.7 19.6a1.1 1.1 0 0 1-1.7-.9z" />,
  gauge: (
    <>
      <path d="M3.6 18.5a9.4 9.4 0 1 1 16.8 0M5 12l2 .6M9.4 6.5l.7 2M18.4 9.2l-5 5.2" />
      <circle cx="12" cy="16" r="1.6" />
    </>
  ),
  arrows: <path d="M3.5 12h17m-13-3.5L4 12l3.5 3.5m9-7 3.5 3.5-3.5 3.5" />,
  info: (
    <>
      <circle cx="12" cy="12" r="8.7" />
      <path d="M10 11.5h2v5h2m-2-9.4v.25" />
    </>
  ),
  plugoff: <path d="M8 3v4m7-4v4M5 8h12v2M6 11c0 3.5 1.9 5.6 5.2 6.2V21m4.3-6.7 5.3 5.3m0-5.3-5.3 5.3" />,
  cores: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 8h3v3H7zM14 8h3v3h-3zM7 14h3m4 0h3" />
    </>
  ),
  pin: (
    <>
      <path d="M12 21s6.8-6.2 6.8-11.4a6.8 6.8 0 0 0-13.6 0C5.2 14.8 12 21 12 21z" />
      <circle cx="12" cy="9.5" r="2.2" />
    </>
  ),
  os: (
    <>
      <rect x="3" y="4" width="18" height="13" rx="2" />
      <path d="M6.8 8 9 10.4l-2.2 2.3M11.5 13h4M9 20h6m-3-3v3" />
    </>
  ),
  bolt: <path d="M13.8 2.8 5.3 13h5.9l-1.1 8.2 8.6-11.6h-5.8z" />,
  plus: <path d="M12 4.8v14.4M4.8 12h14.4" />,
  minus: <path d="M4.8 12h14.4" />,
  pen: <path d="m4 16.1-.8 4.7 4.8-.8L20 8l-4-4zM13.5 6.5l4 4M4.1 16l3.9 4" />,
  trash: <path d="M4 6.8h16M9 6.8V4.7c0-.8.6-1.4 1.4-1.4h3.2c.8 0 1.4.6 1.4 1.4v2.1M6 7.4l.8 11.5a2 2 0 0 0 2 1.9h6.4a2 2 0 0 0 2-1.9L18 7.4M10 10.7l.3 6.1m3.7-6.1-.3 6.1" />,
  okc: (
    <>
      <circle cx="12" cy="12" r="8.7" />
      <path d="m8 12 2.8 2.9 5.4-6" />
    </>
  ),
  xc: (
    <>
      <circle cx="12" cy="12" r="8.7" />
      <path d="m9.4 9.4 5.2 5.2m0-5.2-5.2 5.2" />
    </>
  ),
  reset: <path d="M3.7 10.2A8.6 8.6 0 1 1 4.8 17M3.4 5.7v4.9h4.9M10 16v-3m4 3V9.4" />,
  undo: <path d="M8 4 3.6 8.2 8 12.5M4.2 8.2h9a6 6 0 0 1 0 12h-3" />,
  download: <path d="M12 3v10.5m-4-4 4 4 4-4M4 15.5v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />,
  upload: <path d="M12 14V3.5m-4 4 4-4 4 4M4 15.5v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />,
  check: <path d={CHECK_PATH} />,
  copy: (
    <>
      <rect x="8.5" y="8.5" width="12" height="12" rx="2.2" />
      <path d="M5.5 15.5H5a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2V6" />
    </>
  ),
  x: <path d="m6.3 6.3 11.4 11.4m0-11.4L6.3 17.7" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="3.8" />
      <path d="M12 2.5v2m0 15v2m-9.5-9.5h2m15 0h2M5.2 5.2l1.5 1.5m10.6 10.6 1.5 1.5m0-13.6-1.5 1.5M6.7 17.3l-1.5 1.5" />
    </>
  ),
  fleet: (
    <>
      <rect x="7" y="2.5" width="10" height="5.5" rx="1.4" />
      <rect x="2.5" y="16" width="7" height="5" rx="1.2" />
      <rect x="14.5" y="16" width="7" height="5" rx="1.2" />
      <path d="M12 8.2v4M6 15.8v-3.5h12v3.5" />
    </>
  ),
  agent: (
    <>
      <rect x="5" y="6" width="14" height="13" rx="3" />
      <path d="M12 2.5v3M2.5 10h2.2m14.6 0h2.2M9 19v2m6-2v2m-6-10h.4m5.2 0h.4M9.5 15h5" />
    </>
  ),
  proxy: (
    <>
      <rect x="2" y="8.5" width="5" height="7" rx="1.2" />
      <rect x="17" y="8.5" width="5" height="7" rx="1.2" />
      <path d="M7 12h2l2-6h4m2 6h-2l-2 6H9" />
    </>
  ),
  portForward: (
    <>
      <path d="M3 5h11a4 4 0 0 1 4 4v5m-3-3 3 3 3-3" />
      <rect x="3" y="14" width="8" height="6" rx="1.4" />
      <path d="M6 17h2" />
    </>
  ),
  route: (
    <>
      <path d="M3 17h4l4-10h4" />
      <circle cx="18" cy="7" r="2.5" />
      <circle cx="4.5" cy="17" r="2" />
      <path d="M10 17h7" />
    </>
  ),
  ssh: (
    <>
      <rect x="2.7" y="4.2" width="18.6" height="15.6" rx="2.2" />
      <path d="m6.5 9 3 3-3 3m6.2.1h4.4" />
    </>
  ),
  addNode: (
    <>
      <rect x="3" y="3.5" width="16" height="7" rx="1.7" />
      <path d="M6.3 7h.4m-3.7 7v3.8a2 2 0 0 0 2 2h4.5M14.8 16.5h6.4M18 13.3v6.4" />
    </>
  ),
  addTunnel: (
    <>
      <g transform="translate(0 -2.7)">{TUNNEL}</g>
      <path d="M15 18.7h6.5m-3.25-3.25v6.5" />
    </>
  ),
  addCore: (
    <>
      <rect x="5" y="5" width="12" height="12" rx="2" />
      <path d="M8 2v3m5-3v3M2 8h3m-3 5h3M8 17v3m8.5-1.5h5m-2.5-2.5v5" />
    </>
  ),
  addProxy: (
    <>
      <path d="M2.8 12h5.3l3-7h7m-7 13h2" />
      <rect x="2.5" y="8.5" width="4.3" height="7" rx="1" />
      <path d="M16 17.5h6m-3-3v6" />
    </>
  ),
  addForward: <path d="M3.5 5h9A4.5 4.5 0 0 1 17 9.5v2.8m-3-3 3 3 3-3M3.5 15H8v5H3.5zM14.5 18.5h6m-3-3v6" />,
  bulkInstall: (
    <>
      <rect x="4.5" y="3" width="12" height="4.5" rx="1.2" />
      <rect x="4.5" y="10.5" width="12" height="4.5" rx="1.2" />
      <path d="M6 18h4m9-10v10m-2.5-2.5 2.5 2.5 2.5-2.5" />
    </>
  ),
  inspectNode: (
    <>
      <rect x="3" y="4" width="14.5" height="6" rx="1.3" />
      <path d="M6 7h.3M3 14v3.4c0 1 .8 1.7 1.8 1.7h4" />
      <circle cx="15" cy="15.5" r="3.4" />
      <path d="m17.6 18 3.1 3.1" />
    </>
  ),
  probe: <path d="M3 5h4m10 0h4M3 19h4m10 0h4M2.8 12h4l2.3-4.4 3.2 8.8 2.6-6 2 1.6h4.3" />,
  tune: (
    <>
      <rect x="4.5" y="4.5" width="15" height="15" rx="2.5" />
      <path d="M8 2v2m8-2v2M8 20v2m8-2v2M2 8h2m-2 8h2m16-8h2m-2 8h2M8 9h8m-5-1.4v2.8M8 15h8m-2-1.4v2.8" />
    </>
  ),
  rebuild: <path d="m3 10 8.8-5 8.8 5-8.8 5zM3.2 14l8.6 4.8 8.6-4.8" />,
  flip: (
    <>
      <path d="M3 8h11l-2.5-2.5M21 16H10l2.5 2.5" />
      <circle cx="5" cy="16" r="2" />
      <circle cx="19" cy="8" r="2" />
    </>
  ),
  rotateTarget: (
    <>
      <circle cx="12" cy="12" r="2.3" />
      <path d="M4.1 10.5a8 8 0 0 1 13.4-4.2L20 8.7m0-4.2v4.2h-4.2M20 13.4a8 8 0 0 1-13.5 4.3L4 15.3m0 4.2v-4.2h4.2" />
    </>
  ),
  queue: <path d="M3 5.5h13m-13 5h9m-9 5h5m3 2h10m-3-3 3 3-3 3" />,
  pool: (
    <>
      <rect x="2.5" y="4" width="8" height="6" rx="1.5" />
      <rect x="13.5" y="4" width="8" height="6" rx="1.5" />
      <rect x="8" y="15" width="8" height="5.5" rx="1.4" />
      <path d="M6.5 10v2.5h11V10M12 12.5V15" />
    </>
  ),
  api: <path d="m7.2 6.4-5 5.6 5 5.6m9.6-11.2 5 5.6-5 5.6M14 4.5l-4 15" />,
  token: (
    <>
      <circle cx="7.5" cy="9" r="4" />
      <path d="m11 11.2 8.8 8.2 2-2-2.3-2.1 1.2-1.3-2.5-2.2-1.2 1.2M6.4 8.1h.3" />
    </>
  ),
  backup: (
    <>
      <rect x="3.3" y="4" width="17.4" height="5.3" rx="1.4" />
      <path d="M5 9.8v8.6c0 1.2.9 2.1 2 2.1h10c1.1 0 2-.9 2-2.1V9.8M9 13h6" />
    </>
  ),
  restore: (
    <>
      <path d="M3.3 10.2A8.4 8.4 0 1 1 4.8 17M3.3 5.6v4.7H8" />
      <path d="M12.3 8.4v7m-2.8-2.8 2.8 2.8 2.8-2.8" />
    </>
  ),
  deploy: <path d="m12 3 7 3.7-7 3.7-7-3.7zm-7 7.7v4.9l7 3.6 2.3-1.2M12 10.6v8M18.3 12v8.5m-2.6-2.7 2.6 2.7 2.6-2.7" />,
  filter: <path d="M3.5 4.5h17l-6.6 8.1v6l-4 1.9v-7.9z" />,
  reference: <path d="M12 6.5C9.2 4.2 6.1 4 3 5v13c3.1-1 6.2-.8 9 1.5 2.8-2.3 5.9-2.5 9-1.5V5c-3.1-1-6.2-.8-9 1.5Zm0 .5v12" />,
  edge: <path d="M12 3.5 20 8v8l-8 4.5L4 16V8zM4.5 8.2l7.5 4 7.5-4m-7.5 4v8" />,
  address: (
    <>
      <rect x="2.5" y="5" width="19" height="14" rx="2.2" />
      <circle cx="7" cy="12" r="1.3" />
      <path d="M11.2 10h6.4m-6.4 4H15" />
    </>
  ),
  cfCloud: <path d="M2.8 16.5h16.5a2.8 2.8 0 0 0 0-5.6h-1.6a5.6 5.6 0 0 0-10.9-.5 3.4 3.4 0 0 0-3.6 3.1m.1 6h12M11.5 3v1.4m6.2.9-1.1 1.1" />,
  arCloud: <path d="M6.3 16.3a3.9 3.9 0 0 1-.6-7.7 5.9 5.9 0 0 1 11.5.6 3.7 3.7 0 0 1 .3 7.3H9.6l2.3-4.5m-4.4 8.2h5.6" />,
  rx: <path d="M12 3.8v14m-4.5-4.5 4.5 4.5 4.5-4.5M6 20.5h12" />,
  tx: <path d="M12 18.5v-14m-4.5 4.6L12 4.6l4.5 4.5M6 20.5h12" />,
  forward: <path d="M3.5 12H20m-5.5-5.5L20 12l-5.5 5.5" />,
  back: <path d="M20.5 12H4m5.5-5.5L4 12l5.5 5.5" />,
  grip: <path d="M6 6h2m6 0h3M6 12h2m6 0h3M6 18h2m6 0h3" />,
  unchecked: <circle cx="12" cy="12" r="8.7" />,
}

export function Glyph({ name, ...props }) {
  const body = PATHS[name]
  if (!body) return null
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {body}
    </svg>
  )
}

export default function Icon({ name, color, label }) {
  return (
    <span className="ic" style={color ? { color } : undefined} role={label ? 'img' : undefined}
      aria-label={label} aria-hidden={label ? undefined : true}>
      <Glyph name={name} />
    </span>
  )
}
