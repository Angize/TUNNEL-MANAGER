import { useCallback, useEffect, useRef, useState } from 'react'
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
import useBulk from '../../lib/useBulk.js'
import { BulkBar, BulkButton, BulkSheet } from '../../components/Bulk.jsx'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy, reorderMode } from '../../lib/reorder.js'
import useFlipList from '../../lib/useFlipList.js'
import { splitBuilds } from '../../lib/builds.js'
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
  const builds = splitBuilds(pending, ordered)
  const listBox = useRef(null)
  useFlipList(
    listBox,
    list === null ? null : [...builds.shown.map((l) => l.id), ...builds.cards.map((a) => 'pend_' + a.key)],
    query,
    { hold: reorderMode() || listBusy() }
  )
  const bulk = useBulk({ list: list === null ? null : ordered, command: 'tunnels:checkall', onDone: afterAction })
  const bulkExit = bulk.exit

  useEffect(() => {
    if (!active) bulkExit()
  }, [active, bulkExit])

  return (
    <>

      <div className="tbtnrow">
        <button className="primary glass" onClick={() => setCreating(true)}>
          <Icon name="plus" />
          {T('add_tunnel')}
        </button>
        <BulkButton bulk={bulk} />
      </div>

      <Toolbar value={query} placeholder={T('tun_search')} reorder onSearch={setQuery} />

      <div ref={listBox} className="flist">
        {list === null ? (
          <CardSkeletons kind="tunnel" count={counts.links} />
        ) : builds.shown.length || builds.cards.length ? (
          <>
            {builds.shown.map((link) => (
              <TunnelCard
                key={link.id}
                link={link}
                onEdit={setEditing}
                onReload={afterAction}
                onTag={setTag}
                registerActions={(fn) => bulk.register(link.id, fn)}
                sel={bulk.selecting ? { picked: bulk.picked.has(link.id), pick: bulk.pick } : null}
              />
            ))}
            {builds.cards.map((act) => (
              <PendingCard key={'pend_' + act.key} act={act} tagClass={ctagClass} />
            ))}
            {bulk.selecting ? <div className="bulkpad" /> : null}
          </>
        ) : (
          <div className={'card muted' + (query ? '' : ' empty')}>{query ? T('no_results') : T('tun_empty')}</div>
        )}
      </div>

      {creating ? (
        <TunnelCreateModal onClose={() => setCreating(false)} onCreated={afterAction} />
      ) : null}
      {editing ? (
        <TunnelEditModal link={editing} onClose={() => setEditing(null)} onSaved={afterAction} />
      ) : null}
      <BulkBar bulk={bulk} active={active} />
      <BulkSheet bulk={bulk} links={ordered} />
    </>
  )
}
