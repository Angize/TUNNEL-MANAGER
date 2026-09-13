export function Kv({ children }) {
  return (
    <div className="kv">
      <span className="tnarrow kvgut" aria-hidden="true">
        ↔
      </span>
      {children}
    </div>
  )
}

export function KvRow({ label, side, wide, mono, children }) {
  return (
    <dl className={'kvc' + (wide ? ' w' : side === 'l' ? ' l' : '')}>
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{children}</dd>
    </dl>
  )
}

export function Sep() {
  return <span className="sep">·</span>
}
