import { useCallback, useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import Reveal from '../../components/Reveal.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import NodeCard from './NodeCard.jsx'
import NodeAddModal from './NodeAddModal.jsx'
import { useBulk } from '../../state/BulkInstallContext.jsx'
import NodeEditModal from './NodeEditModal.jsx'
import NodeDetailsModal from './NodeDetailsModal.jsx'
import KernelTuneModal from './KernelTuneModal.jsx'
import DeleteNodeModal from './DeleteNodeModal.jsx'
import MovedIpModal from './MovedIpModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import usePolledData from '../../lib/usePolledData.js'
import usePageQuery from '../../lib/pageQuery.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy, reorderMode } from '../../lib/reorder.js'
import useFlipList from '../../lib/useFlipList.js'
import './nodes.css'

function isCentralStale(node) {
  const got = (node.info && node.info.central) || ''
  const want = node.central_want || ''
  return !!(got && want && got !== want)
}

function StaleBanner({ count }) {
  if (!count) return null
  return (
    <div className="rdbar">
      <Icon name="warn" />
      <div className="rdtx">
        <b>{count === 1 ? T('cn_stale_one') : T('cn_stale_n').replace('{n}', count)}</b>
        <span>{T('cn_stale_sub')}</span>
      </div>
    </div>
  )
}

export default function NodesPage({ active }) {
  const [query, setQuery] = usePageQuery('nodes')
  const [overrides, setOverrides] = useState({})
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState(null)
  const [details, setDetails] = useState(null)
  const [tuning, setTuning] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [moved, setMoved] = useState(null)
  const settled = useRef(0)

  const load = useCallback(async (onProgress) => {
    if (listBusy()) return undefined
    const epoch = settled.current
    const r = await apiGet('nodes?q=' + encodeURIComponent(query), onProgress)
    return { nodes: r.nodes, windowHours: num(r.uptime_window) || 1, epoch }
  }, [query])

  const [data, reload, progress] = usePolledData(load, query, active)
  const bulk = useBulk()
  const { asked, took, setDialog } = bulk
  const closeAdd = () => {
    setAdding(false)
    if (!bulk.batch || bulk.batch.done) bulk.finish()
  }

  useEffect(() => {
    if (!asked) return
    took()
    setAdding(true)
  }, [asked, took])

  useEffect(() => {
    setDialog(adding)
    return () => setDialog(false)
  }, [adding, setDialog])

  const onToggle = useCallback(async (node) => {
    const disabled = node.disabled !== true
    const r = await apiPost('node-toggle', { id: node.id, disabled })
    if (!(r.ok && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    const epoch = ++settled.current
    setOverrides((prev) => ({ ...prev, [node.id]: { disabled, epoch } }))
    toast(disabled ? T('nd_hidden') : T('nd_shown'), 'ok')
  }, [])

  const nodes = (data ? data.nodes : []).map((n) => {
    const o = overrides[n.id]
    return o && o.epoch > data.epoch ? { ...n, disabled: o.disabled } : n
  })
  const staleCount = nodes.filter(isCentralStale).length

  const order = useCardReorder('nodes', nodes.map((n) => n.id), reload)
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const ordered = order.map((id) => byId.get(id)).filter(Boolean)
  const live = (snapshot) => byId.get(snapshot.id) || snapshot
  const listBox = useRef(null)
  useFlipList(listBox, data === null ? null : ordered.map((n) => n.id), query, { hold: reorderMode() || listBusy() })

  return (
    <>
      {data ? (
        <Reveal show={staleCount > 0}>
          <StaleBanner count={staleCount} />
        </Reveal>
      ) : null}
      <div className="tbtnrow">
        <button className="primary glass" onClick={() => setAdding(true)}>
          <Icon name="plus" />
          {T('add_node')}
        </button>
      </div>

      <div className="sec">
        <Icon name="server" color="var(--acc-tx)" />
        {T('nodes_fleet')}
      </div>

      <Toolbar value={query} placeholder={T('nodes_search')} reorder onSearch={setQuery} />

      <LoadBar on={data === null} value={progress} />
      <div ref={listBox} className="flist">
        {data === null ? null : (
          <>
            {ordered.length ? (
              ordered.map((node) => (
                <NodeCard
                  key={node.id}
                  node={node}
                  windowHours={data.windowHours}
                  onToggle={onToggle}
                  onChanged={reload}
                  onEdit={setEditing}
                  onDetails={setDetails}
                  onTune={setTuning}
                  onDelete={setDeleting}
                  onMovedIp={setMoved}
                />
              ))
            ) : (
              <div className={'card muted' + (query ? '' : ' empty')}>{query ? T('no_results') : T('nodes_empty')}</div>
            )}
          </>
        )}
      </div>

      {adding ? <NodeAddModal bulk={bulk} onClose={closeAdd} onAdded={reload} /> : null}
      {editing ? (
        <NodeEditModal node={editing} onClose={() => setEditing(null)} onSaved={reload} />
      ) : null}
      {details ? <NodeDetailsModal node={live(details)} onClose={() => setDetails(null)} /> : null}
      {tuning ? <KernelTuneModal node={tuning} onClose={() => setTuning(null)} /> : null}
      {deleting ? (
        <DeleteNodeModal node={live(deleting)} onClose={() => setDeleting(null)} onDeleted={reload} />
      ) : null}
      {moved ? (
        <MovedIpModal node={moved} onClose={() => setMoved(null)} onAdopted={reload} />
      ) : null}
    </>
  )
}
