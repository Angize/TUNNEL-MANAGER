import { useCallback, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import { CardSkeletons } from '../../components/Skeleton.jsx'
import ProxyCard from './ProxyCard.jsx'
import ProxyModal from './ProxyModal.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import usePolledData from '../../lib/usePolledData.js'
import './proxies.css'

const ADD_BUTTON_STYLE = {
  margin: '0 0 14px',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
}

export default function ProxiesPage() {
  const [editing, setEditing] = useState(undefined)

  const load = useCallback(async () => {
    const r = await apiGet('proxies')
    return r.proxies || []
  }, [])

  const [list, reload] = usePolledData(load)

  return (
    <>
      <PageHead icon="globe" titleKey="nav_proxies" subKey="px_sub" />
      <button className="primary" onClick={() => setEditing(null)} style={ADD_BUTTON_STYLE}>
        <Icon name="plus" />
        {T('px_add')}
      </button>

      <div>
        {list === null ? (
          <CardSkeletons />
        ) : list.length ? (
          list.map((proxy) => (
            <ProxyCard
              key={proxy.id}
              proxy={proxy}
              onEdit={setEditing}
              onChanged={reload}
            />
          ))
        ) : (
          <div className="card muted">{T('px_empty')}</div>
        )}
      </div>

      {editing !== undefined ? (
        <ProxyModal proxy={editing} onClose={() => setEditing(undefined)} onSaved={reload} />
      ) : null}
    </>
  )
}
