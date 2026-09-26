import { T, TF } from '../../i18n/fa.js'
import { checkable } from '../../lib/keys.js'

function NodeRow({ node, on, proxyId, onToggle }) {
  const other = node.proxy_on && node.proxy_id !== proxyId ? node.proxy_name : ''
  return (
    <div className={'msrow' + (on ? ' sel' : '')} {...checkable('checkbox', on, onToggle)}>
      <span className="mscheck" />
      <span className="mono pxnname">{node.name}</span>
      {other ? <span className="pxother">{TF('px_on_other', { p: other })}</span> : null}
      <span className="mssub">{node.host}</span>
    </div>
  )
}

export default function ProxyNodes({ proxyId, nodes, picked, onPick }) {
  if (nodes === null) return <div className="muted pxnmsg">{T('px_nodes_loading')}</div>
  if (nodes === false) return <div className="pxnmsg pxnerr">{T('px_nodes_err')}</div>
  if (!nodes.length) return <div className="muted pxnmsg">{T('px_nodes_none')}</div>

  const all = picked.size === nodes.length
  const some = picked.size > 0 && !all
  const toggle = (id) =>
    onPick((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const toggleAll = () =>
    onPick((prev) => (prev.size === nodes.length ? new Set() : new Set(nodes.map((n) => n.id))))

  return (
    <div className="mslist">
      <div
        className={'msrow pxall' + (all ? ' sel' : some ? ' part' : '')}
        {...checkable('checkbox', all, toggleAll)}
        aria-checked={all ? 'true' : some ? 'mixed' : 'false'}
      >
        <span className="mscheck" />
        <b>{T('px_nodes_all')}</b>
        <span className="mssub">
          {picked.size}/{nodes.length}
        </span>
      </div>
      <div className="pxnlist">
        {nodes.map((node) => (
          <NodeRow
            key={node.id}
            node={node}
            on={picked.has(node.id)}
            proxyId={proxyId}
            onToggle={() => toggle(node.id)}
          />
        ))}
      </div>
    </div>
  )
}
