import { useCallback, useEffect, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import PendingCard from '../../components/PendingCard.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import CoreCard from './CoreCard.jsx'
import CoreFormModal from './form/CoreFormModal.jsx'
import { tagClassForFamily } from './carrier.js'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost, NET_TIMEOUT } from '../../lib/api.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy } from '../../lib/reorder.js'
import { useActs } from '../../state/ActsContext.jsx'
import './core.css'

export default function CorePage() {
  const { pendingFor, buildCount, refresh: actsRefresh } = useActs()
  const [query, setQuery] = useState('')
  const [checking, setChecking] = useState(false)
  const [tagOverrides, setTagOverrides] = useState({})
  const [edges, setEdges] = useState({})
  const [editing, setEditing] = useState(null)
  const checkRefs = useRef({})

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('fleet?kind=core&q=' + encodeURIComponent(query))
    return r.links || []
  }, [query])

  const [list, reload] = usePolledData(load, query)

  useEffect(() => {
    reload()
  }, [buildCount, reload])

  useEffect(() => {
    const pooled = (list || []).filter((l) => l.transport === 'ws' && l.ws_pool)
    if (!pooled.length) return undefined
    let alive = true
    const tick = async () => {
      await Promise.all(
        pooled.map(async (link) => {
          const r = await apiPost('edge-status', { id: link.id })
          if (!alive) return
          if (r.ok && r.d && r.d.ok && r.d.pool && r.d.active) {
            setEdges((prev) =>
              prev[link.id] === r.d.active ? prev : { ...prev, [link.id]: r.d.active }
            )
          }
        })
      )
    }
    tick()
    return () => {
      alive = false
    }
  }, [list])

  const setTag = useCallback(async (link, tag) => {
    const previous = num(link.tag)
    setTagOverrides((prev) => ({ ...prev, [link.id]: tag }))
    try {
      const r = await apiPost('link-tag', { id: link.id, tag }, NET_TIMEOUT)
      if (r.ok && r.d.ok) return
      toast((r.d && r.d.error) || T('tag_err'), 'err')
    } catch {
      toast(T('tag_err'), 'err')
    }
    setTagOverrides((prev) => ({ ...prev, [link.id]: previous }))
  }, [])

  const checkAll = async () => {
    const links = list || []
    if (!links.length) {
      toast(T('no_tunnel_check'), 'err')
      return
    }
    setChecking(true)
    try {
      await Promise.all(
        links.map((link) => {
          const run = checkRefs.current[link.id]
          return run ? run() : Promise.resolve()
        })
      )
    } finally {
      setChecking(false)
    }
    toast(T('checkall_done'), 'ok')
  }

  const closeForm = useCallback(() => setEditing(null), [])

  const afterAction = useCallback(async () => {
    await actsRefresh()
    await reload()
  }, [actsRefresh, reload])

  const pending = pendingFor('core')
  const links = (list || []).map((link) =>
    tagOverrides[link.id] === undefined ? link : { ...link, tag: tagOverrides[link.id] }
  )

  const order = useCardReorder('core', links.map((l) => l.id), afterAction)
  const byId = new Map(links.map((l) => [l.id, l]))
  const ordered = order.map((id) => byId.get(id)).filter(Boolean)

  return (
    <>
      <PageHead icon="cpu" titleKey="nav_core" subKey="core_sub" />

      <div className="tbtnrow">
        <button className="primary" onClick={() => setEditing({})}>
          <Icon name="plus" />
          {T('core_add')}
        </button>
        <button
          className="chkall"
          disabled={checking}
          style={checking ? { opacity: 0.6 } : undefined}
          onClick={checkAll}
        >
          <Icon name="activity" />
          {T('check_all')}
        </button>
      </div>

      <Toolbar value={query} placeholder={T('core_search')} reorder onSearch={setQuery} />

      <div className="cardgrid">
        {list === null ? (
          <CardSkeletons />
        ) : links.length || pending.length ? (
          <>
            {ordered.map((link) => (
              <CoreCard
                key={link.id}
                link={link}
                activeEdge={edges[link.id] || ''}
                onEdit={setEditing}
                onReload={afterAction}
                onTag={setTag}
                registerCheck={(fn) => {
                  checkRefs.current[link.id] = fn
                }}
              />
            ))}
            {pending.map((act) => (
              <PendingCard key={'pend_' + act.key} act={act} tagClass={tagClassForFamily} />
            ))}
          </>
        ) : (
          <div className="card muted">{query ? T('no_results') : T('core_empty')}</div>
        )}
      </div>

      {editing ? (
        <CoreFormModal
          link={editing.id ? editing : null}
          onClose={closeForm}
          onDone={afterAction}
        />
      ) : null}
    </>
  )
}
