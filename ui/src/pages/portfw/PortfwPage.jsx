import { useCallback, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import PortfwCard from './PortfwCard.jsx'
import PortfwAddModal from './PortfwAddModal.jsx'
import PortfwEditModal from './PortfwEditModal.jsx'
import { T } from '../../i18n/fa.js'
import { useSummary } from '../../state/SummaryContext.jsx'
import { apiGet } from '../../lib/api.js'
import { readError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import usePolledData from '../../lib/usePolledData.js'
import usePageQuery from '../../lib/pageQuery.js'
import useCardReorder from '../../lib/useCardReorder.js'
import { listBusy } from '../../lib/reorder.js'

const ADD_BUTTON_STYLE = {
  margin: '0 0 14px',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
}

export default function PortfwPage({ active }) {
  const { counts } = useSummary()
  const [query, setQuery] = usePageQuery('portfw')
  const [nodes, setNodes] = useState([])
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState(null)

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('portfw-list?q=' + encodeURIComponent(query))
    return r.portfw.filter((x) => x.name)
  }, [query])

  const [list, reload] = usePolledData(load, query, active)

  const loadNodes = useCallback(async () => {
    try {
      const r = await apiGet('node-names')
      setNodes(r.nodes)
      return r.nodes
    } catch (e) {
      toast(readError(e), 'err')
      return null
    }
  }, [])

  const openAdd = async () => {
    const all = await loadNodes()
    if (!all) return
    if (!all.some((n) => n.online)) {
      toast(T('pf_no_online'), 'err')
      return
    }
    setAdding(true)
  }

  const openEdit = async (item) => {
    if (await loadNodes()) setEditing(item)
  }

  const items = list || []
  const order = useCardReorder('portfw', items.map((x) => x.node_id + x.name), reload)
  const byId = new Map(items.map((x) => [x.node_id + x.name, x]))
  const ordered = order.map((id) => byId.get(id)).filter(Boolean)

  return (
    <>
      <button className="primary" onClick={openAdd} style={ADD_BUTTON_STYLE}>
        <Icon name="plus" />
        {T('pf_add')}
      </button>

      <div className="sec">
        <Icon name="activity" color="var(--acc)" />
        {T('pf_active')}
      </div>

      <Toolbar value={query} placeholder={T('pf_search')} reorder onSearch={setQuery} />

      <div>
        {list === null ? (
          <CardSkeletons kind="portfw" count={counts.portfw} />
        ) : ordered.length ? (
          ordered.map((item) => (
            <PortfwCard
              key={item.node_id + item.name}
              item={item}
              onEdit={openEdit}
              onChanged={reload}
            />
          ))
        ) : (
          <div className="card muted">{query ? T('no_results') : T('pf_empty')}</div>
        )}
      </div>

      {adding ? (
        <PortfwAddModal
          nodes={nodes.filter((n) => n.online)}
          onClose={() => setAdding(false)}
          onCreated={reload}
        />
      ) : null}

      {editing ? (
        <PortfwEditModal
          item={editing}
          nodes={nodes}
          onClose={() => setEditing(null)}
          onSaved={reload}
        />
      ) : null}
    </>
  )
}
