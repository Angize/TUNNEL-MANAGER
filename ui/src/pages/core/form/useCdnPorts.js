import { useEffect, useState } from 'react'
import { apiPost } from '../../../lib/api.js'

function emptied(rules, hosts) {
  const mine = new Set(hosts)
  return rules.filter((r) => r.hosts.length && r.hosts.every((h) => mine.has(h))).length
}

export default function useCdnPorts(ask) {
  const sig = ask && Object.keys(ask.zones).length ? JSON.stringify(ask) : ''
  const [got, setGot] = useState({ sig: '', infos: null })

  useEffect(() => {
    if (!sig) return undefined
    let alive = true
    const { zones, ...rest } = JSON.parse(sig)
    const names = Object.keys(zones)
    Promise.all(names.map((zone) => apiPost('cdn-ports', { ...rest, zone }))).then((rs) => {
      if (!alive) return
      const infos = rs.flatMap((r, k) => (r.ok && r.d.ok ? [{ ...r.d, freed: emptied(r.d.rules, zones[names[k]]) }] : []))
      setGot({ sig, infos: infos.length ? infos : null })
    })
    return () => {
      alive = false
    }
  }, [sig])

  return sig && got.sig === sig ? got.infos : null
}
