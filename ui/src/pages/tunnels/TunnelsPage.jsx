import { useCallback, useEffect, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import PendingCard from '../../components/PendingCard.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import TunnelCard from './TunnelCard.jsx'
import TunnelCreateModal from './TunnelCreateModal.jsx'
import TunnelEditModal from './TunnelEditModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost, NET_TIMEOUT } from '../../lib/api.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import usePageQuery from '../../lib/pageQuery.js'
import { registerCommand } from '../../lib/pageCommand.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy } from '../../lib/reorder.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import './tunnels.css'

function ctagClass(family) {
  return family
}

export default function TunnelsPage() {
  const { pendingFor, buildCount, refresh: actsRefresh } = useActs()
  const { counts } = useSummary()
  const [query, setQuery] = usePageQuery('tunnels')
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState(null)
  const [checking, setChecking] = useState(false)
  const [tagOverrides, setTagOverrides] = useState({})
  const checkRefs = useRef({})
  const checkAllRef = useRef(null)

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('fleet?kind=tunnels&q=' + encodeURIComponent(query))
    return r.links || []
  }, [query])

  const [list, reload] = usePolledData(load, query)

  useEffect(() => {
    reload()
  }, [buildCount, reload])

  const setTag = useCallback(
    async (link, tag) => {
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
    },
    []
  )

  useEffect(() => {
    const off = [
      registerCommand('tunnels:create', () => setCreating(true)),
      registerCommand('tunnels:checkall', () => checkAllRef.current && checkAllRef.current()),
    ]
    return () => off.forEach((fn) => fn())
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

  checkAllRef.current = checkAll

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
      <PageHead icon="link" titleKey="tun_title" subKey="tun_sub" />

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

      <div className="cardgrid">
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
