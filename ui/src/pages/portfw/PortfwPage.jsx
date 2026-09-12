import { useCallback, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import PortfwCard from './PortfwCard.jsx'
import PortfwAddModal from './PortfwAddModal.jsx'
import PortfwEditModal from './PortfwEditModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { toast } from '../../lib/toast.js'
import usePolledData from '../../lib/usePolledData.js'

const ADD_BUTTON_STYLE = {
  margin: '0 0 14px',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
}

export default function PortfwPage() {
  const [query, setQuery] = useState('')
  const [nodes, setNodes] = useState([])
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState(null)

  const load = useCallback(async () => {
    const r = await apiGet('portfw-list?q=' + encodeURIComponent(query))
    return (r.portfw || []).filter((x) => x.name)
  }, [query])

  const [list, reload] = usePolledData(load, query)

  const loadNodes = useCallback(async () => {
    let r = {}
    try {
      r = await apiGet('node-names')
    } catch {
      r = {}
    }
    const all = r.nodes || []
    setNodes(all)
    return all
  }, [])

  const openAdd = async () => {
    const all = await loadNodes()
    if (!all.some((n) => n.online)) {
      toast(T('pf_no_online'), 'err')
      return
    }
    setAdding(true)
  }

  const openEdit = async (item) => {
    await loadNodes()
    setEditing(item)
  }

  return (
    <>
      <PageHead icon="fwd" titleKey="nav_portfw" subKey="pf_sub" />
      <button className="primary" onClick={openAdd} style={ADD_BUTTON_STYLE}>
        <Icon name="plus" />
        {T('pf_add')}
      </button>

      <div className="sec">
        <Icon name="activity" color="var(--acc)" />
        {T('pf_active')}
      </div>

      <Toolbar value={query} placeholder={T('pf_search')} onSearch={setQuery} />

      <div className="cardgrid">
        {list === null ? (
          <CardSkeletons />
        ) : list.length ? (
          list.map((item) => (
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
