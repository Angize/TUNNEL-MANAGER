import { useCallback, useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import PendingCard from '../../components/PendingCard.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import CoreCard from './CoreCard.jsx'
import CoreFormModal from './form/CoreFormModal.jsx'
import { tagClassForFamily } from './carrier.js'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost, NET_TIMEOUT } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { registerCommand } from '../../lib/pageCommand.js'
import useBulk from '../../lib/useBulk.js'
import { BulkBar, BulkButton, BulkSheet } from '../../components/Bulk.jsx'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import usePageQuery from '../../lib/pageQuery.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy } from '../../lib/reorder.js'
import { splitBuilds } from '../../lib/builds.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import './core.css'

export default function CorePage({ active }) {
  const { pendingFor, buildCount, refresh: actsRefresh } = useActs()
  const { counts } = useSummary()
  const [query, setQuery] = usePageQuery('core')
  const [tagOverrides, setTagOverrides] = useState({})
  const [edges, setEdges] = useState({})
  const [editing, setEditing] = useState(null)
  const mounted = useRef(true)
  const polledIds = useRef(new Set())
  const edgeFlight = useRef(new Set())

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('fleet?kind=core&q=' + encodeURIComponent(query))
    return r.links
  }, [query])

  const [list, reload] = usePolledData(load, query, active)

  useEffect(() => {
    reload()
  }, [buildCount, reload])

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    const pooled = (list || []).filter((l) => l.transport === 'ws' && l.ws_pool && l.enabled !== false)
    const polled = new Set(pooled.map((l) => l.id))
    polledIds.current = polled
    setEdges((prev) =>
      Object.keys(prev).every((id) => polled.has(id))
        ? prev
        : Object.fromEntries(Object.entries(prev).filter(([id]) => polled.has(id)))
    )
    for (const link of pooled) {
      if (edgeFlight.current.has(link.id)) continue
      edgeFlight.current.add(link.id)
      apiPost('edge-status', { id: link.id }).then((r) => {
        edgeFlight.current.delete(link.id)
        if (!mounted.current || !polledIds.current.has(link.id) || !(r.ok && r.d.ok)) return
        const active = r.d.pool ? String(r.d.active || '') : ''
        setEdges((prev) => (prev[link.id] === active ? prev : { ...prev, [link.id]: active }))
      })
    }
  }, [list])

  const setTag = useCallback(async (link, tag) => {
    const previous = num(link.tag)
    setTagOverrides((prev) => ({ ...prev, [link.id]: tag }))
    const r = await apiPost('link-tag', { id: link.id, tag }, NET_TIMEOUT)
    if (r.ok && r.d.ok) return
    toast(postError(r, 'tag_err'), 'err')
    setTagOverrides((prev) => ({ ...prev, [link.id]: previous }))
  }, [])

  useEffect(() => registerCommand('core:create', () => setEditing({})), [])

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
  const builds = splitBuilds(pending, ordered)
  const bulk = useBulk({ list: list === null ? null : ordered, command: 'core:checkall', onDone: afterAction })
  const bulkExit = bulk.exit

  useEffect(() => {
    if (!active) bulkExit()
  }, [active, bulkExit])

  return (
    <>

      <div className="tbtnrow">
        <button className="primary glass" onClick={() => setEditing({})}>
          <Icon name="plus" />
          {T('core_add')}
        </button>
        <BulkButton bulk={bulk} />
      </div>

      <Toolbar value={query} placeholder={T('core_search')} reorder onSearch={setQuery} />

      <div>
        {list === null ? (
          <CardSkeletons kind="tunnel" count={counts.core} />
        ) : builds.shown.length || builds.cards.length ? (
          <>
            {builds.shown.map((link) => (
              <CoreCard
                key={link.id}
                link={link}
                activeEdge={edges[link.id] || ''}
                onEdit={setEditing}
                onReload={afterAction}
                onTag={setTag}
                registerActions={(fn) => bulk.register(link.id, fn)}
                sel={bulk.selecting ? { picked: bulk.picked.has(link.id), pick: bulk.pick } : null}
              />
            ))}
            {builds.cards.map((act) => (
              <PendingCard key={'pend_' + act.key} act={act} tagClass={tagClassForFamily} />
            ))}
            {bulk.selecting ? <div className="bulkpad" /> : null}
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
      <BulkBar bulk={bulk} active={active} />
      <BulkSheet bulk={bulk} links={ordered} core />
    </>
  )
}
