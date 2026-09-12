export function Bar({ w, h, r }) {
  return <span className="sk" style={{ width: w, height: (h || 12) + 'px', borderRadius: r != null ? r + 'px' : undefined }} />
}

export function AccCardSkeleton() {
  return (
    <div className="card acc">
      <div className="chead">
        <span className="sk" style={{ width: 38, height: 22, borderRadius: 20, flex: '0 0 auto' }} />
        <div className="hmain">
          <div className="hrow1">
            <Bar w="96px" h={13} />
            <Bar w="40px" h={15} r={20} />
            <span style={{ marginInlineStart: 'auto', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Bar w="58px" h={11} />
              <span className="sk" style={{ width: 14, height: 8 }} />
              <Bar w="58px" h={11} />
            </span>
          </div>
        </div>
        <span className="sk" style={{ width: 14, height: 14, borderRadius: 4, flex: '0 0 auto' }} />
      </div>
    </div>
  )
}

export function CardSkeletons({ count }) {
  const n = Math.max(3, Math.min(8, count || 6))
  return Array.from({ length: n }, (_, i) => <AccCardSkeleton key={i} />)
}
