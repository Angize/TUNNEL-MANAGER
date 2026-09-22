import { useCallback, useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import PendingCard from '../../components/PendingCard.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import TunnelCard from './TunnelCard.jsx'
import TunnelCreateModal from './TunnelCreateModal.jsx'
import TunnelEditModal from './TunnelEditModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost, NET_TIMEOUT } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import usePageQuery from '../../lib/pageQuery.js'
import { registerCommand } from '../../lib/pageCommand.js'
import useCheckAll from '../../lib/useCheckAll.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy } from '../../lib/reorder.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import './tunnels.css'

function ctagClass(family) {
  return family
}

export default function TunnelsPage({ active }) {
  const { pendingFor, buildCount, refresh: actsRefresh } = useActs()
  const { counts } = useSummary()
  const [query, setQuery] = usePageQuery('tunnels')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState(null)
  const [tagOverrides, setTagOverrides] = useState({})

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('fleet?kind=tunnels&q=' + encodeURIComponent(query))
    return r.links
  }, [query])

  const [list, reload] = usePolledData(load, query, active)
  const { checking, checkAll, checkRefs } = useCheckAll('tunnels:checkall', list)

  useEffect(() => {
    reload()
  }, [buildCount, reload])

  const setTag = useCallback(
    async (link, tag) => {
      const previous = num(link.tag)
      setTagOverrides((prev) => ({ ...prev, [link.id]: tag }))
      const r = await apiPost('link-tag', { id: link.id, tag }, NET_TIMEOUT)
      if (r.ok && r.d.ok) return
      toast(postError(r, 'tag_err'), 'err')
      setTagOverrides((prev) => ({ ...prev, [link.id]: previous }))
    },
    []
  )

  useEffect(() => {
    setTagOverrides((prev) => {
      const next = {}
      for (const [id, tag] of Object.entries(prev)) {
        const got = (list || []).find((x) => x.id === id)
        if (!got || num(got.tag) !== tag) next[id] = tag
      }
      return Object.keys(next).length === Object.keys(prev).length ? prev : next
    })
  }, [list])

  useEffect(() => registerCommand('tunnels:create', () => setCreating(true)), [])

  const afterAction = useCallback(async () => {
    await actsRefresh()
    await reload()
  }, [actsRefresh, reload])

  const pending = pendingFor('tunnels')
  const links = (list || []).map((link) =>
    tagOverrides[link.id] === undefined ? link : { ...link, tag: tagOverrides[link.id] }
  )

  const order = useCardReorder('tunnels', links.map((l) => l.id), afterAction)
  const byId = new Map(links.map((l) => [l.id, l]))
  const ordered = order.map((id) => byId.get(id)).filter(Boolean)

  return (
    <>

      <div className="tbtnrow">
        <button className="primary" onClick={() => setCreating(true)}>
          <Icon name="plus" />
          {T('add_tunnel')}
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

      <Toolbar value={query} placeholder={T('tun_search')} reorder onSearch={setQuery} />

      <div>
        {list === null ? (
          <CardSkeletons kind="tunnel" count={counts.links} />
        ) : links.length || pending.length ? (
          <>
            {ordered.map((link) => (
              <TunnelCard
                key={link.id}
                link={link}
                onEdit={setEditing}
                onReload={afterAction}
                onTag={setTag}
                registerCheck={(fn) => {
                  checkRefs.current[link.id] = fn
                }}
              />
            ))}
            {pending.map((act) => (
              <PendingCard key={'pend_' + act.key} act={act} tagClass={ctagClass} />
            ))}
          </>
        ) : (
          <div className="card muted">{query ? T('no_results') : T('tun_empty')}</div>
        )}
      </div>

      {creating ? (
        <TunnelCreateModal onClose={() => setCreating(false)} onCreated={afterAction} />
      ) : null}
      {editing ? (
        <TunnelEditModal link={editing} onClose={() => setEditing(null)} onSaved={afterAction} />
      ) : null}
    </>
  )
}
