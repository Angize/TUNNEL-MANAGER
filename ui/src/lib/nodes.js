export function nodeIps(nodes, id) {
  const node = (nodes || []).find((n) => n.id === id)
  if (!node || !node.info || !node.info.ips) return []
  const out = []
  for (const list of Object.values(node.info.ips)) {
    for (const ip of list || []) if (!out.includes(ip)) out.push(ip)
  }
  return out
}

export function ipItems(ips) {
  return (ips || []).map((ip) => ({ v: ip, label: ip }))
}

export function nodeLabel(items, id) {
  const item = (items || []).find((x) => x.v === id)
  return (item && item.label) || id
}

export function seedIp(ips, chosen, stored) {
  if (chosen && ips.includes(chosen)) return chosen
  if (stored && ips.includes(stored)) return stored
  return ips[0]
}

export function endIp(ips, chosen, stored) {
  if (ips.length > 1) return seedIp(ips, chosen, stored) || ''
  return stored && ips.includes(stored) ? stored : ''
}

export function nodeItemsKeeping(nodes, keep) {
  const out = []
  const seen = {}
  for (const node of nodes || []) {
    if (!node.online || node.hidden) continue
    seen[node.id] = true
    out.push({ v: node.id, label: node.name, sub: node.host })
  }
  for (const [id, name] of keep) {
    if (!id || seen[id]) continue
    seen[id] = true
    const node = (nodes || []).find((x) => x.id === id)
    out.push({ v: id, label: (node && node.name) || name || id, sub: (node && node.host) || '' })
  }
  return out
}

export function nodeItemsForEdit(nodes, link) {
  return nodeItemsKeeping(nodes, [
    [link.a_node, link.a_name],
    [link.b_node, link.b_name],
  ])
}
