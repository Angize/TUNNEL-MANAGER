export function Kv({ children }) {
  return <dl className="kv">{children}</dl>
}

export function KvRow({ label, wide, mono, children }) {
  return (
    <>
      <dt className={wide ? 'w' : undefined}>{label}</dt>
      <dd className={(wide ? 'w' : '') + (mono ? ' mono' : '')}>{children}</dd>
    </>
  )
}

export function Sep() {
  return <span className="sep">·</span>
}
