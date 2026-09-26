import { useCallback, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import ProxyCard from './ProxyCard.jsx'
import ProxyModal from './ProxyModal.jsx'
import { T } from '../../i18n/fa.js'
import { useSummary } from '../../state/SummaryContext.jsx'
import { apiGet } from '../../lib/api.js'
import usePolledData from '../../lib/usePolledData.js'
import { listBusy } from '../../lib/reorder.js'
import useFlipList from '../../lib/useFlipList.js'
import './proxies.css'

export default function ProxiesPage({ active }) {
  const { counts } = useSummary()
  const [editing, setEditing] = useState(undefined)
  const [edits, setEdits] = useState({})

  const load = useCallback(async () => {
    if (listBusy()) return undefined
    const r = await apiGet('proxies')
    return r.proxies
  }, [])

  const [list, reload] = usePolledData(load, null, active)

  const listBox = useRef(null)
  const cardKey = (proxy) => proxy.id + ':' + (edits[proxy.id] || 0)
  useFlipList(listBox, list === null ? null : list.map(cardKey), null, { hold: listBusy() })

  const saved = (id) => {
    if (id) setEdits((prev) => ({ ...prev, [id]: (prev[id] || 0) + 1 }))
    reload()
  }

  return (
    <>
      <div className="tbtnrow">
        <button className="primary glass" onClick={() => setEditing(null)}>
          <Icon name="plus" />
          {T('px_add')}
        </button>
      </div>

      <div ref={listBox} className="flist">
        {list === null ? (
          <CardSkeletons kind="proxy" count={counts.proxies} />
        ) : list.length ? (
          list.map((proxy) => (
            <ProxyCard
              key={cardKey(proxy)}
              proxy={proxy}
              onEdit={setEditing}
              onChanged={reload}
            />
          ))
        ) : (
          <div className="card muted empty">{T('px_empty')}</div>
        )}
      </div>

      {editing !== undefined ? (
        <ProxyModal
          proxy={editing}
          onClose={() => setEditing(undefined)}
          onSaved={() => saved(editing && editing.id)}
        />
      ) : null}
    </>
  )
}
