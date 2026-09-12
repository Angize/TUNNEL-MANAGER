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
