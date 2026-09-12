import { useCallback, useEffect, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import ProxyCard from './ProxyCard.jsx'
import ProxyModal from './ProxyModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { setPageRefresh } from '../../lib/poll.js'
import './proxies.css'

export default function ProxiesPage() {
  const [list, setList] = useState(null)
  const [editing, setEditing] = useState(undefined)
  const alive = useRef(true)

  const load = useCallback(async () => {
    let r = {}
    try {
      r = await apiGet('proxies')
    } catch {
      r = {}
    }
    if (alive.current) setList(r.proxies || [])
  }, [])

  useEffect(() => {
    alive.current = true
    load()
    const off = setPageRefresh(load)
    return () => {
      alive.current = false
      off()
    }
  }, [load])

  return (
    <>
      <PageHead icon="globe" titleKey="nav_proxies" subKey="px_sub" />
      <button
        className="primary"
        onClick={() => setEditing(null)}
        style={{ margin: '0 0 14px', display: 'inline-flex', alignItems: 'center', gap: 6 }}
      >
        <Icon name="plus" />
        {T('px_add')}
      </button>

      <div>
        {list === null ? (
          <CardSkeletons />
        ) : list.length ? (
          list.map((p) => (
            <ProxyCard key={p.id} proxy={p} onEdit={setEditing} onChanged={load} />
          ))
        ) : (
          <div className="card muted">{T('px_empty')}</div>
        )}
      </div>

      {editing !== undefined ? (
        <ProxyModal
          proxy={editing}
          onClose={() => setEditing(undefined)}
          onSaved={load}
        />
      ) : null}
    </>
  )
}
