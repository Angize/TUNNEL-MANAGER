import { useEffect, useState } from 'react'
import { WarnCap } from './controls.jsx'
import { wsProfOf } from './gates.js'
import { apiPost } from '../../../lib/api.js'

export default function ZoneNotes({ form, zones }) {
  const sig = JSON.stringify([zones, { ws_tls: !!form.WsTls, cdn_carrier: wsProfOf(form.Cdn) }])
  const [got, setGot] = useState({ sig: '', notes: [] })

  useEffect(() => {
    let alive = true
    const [zs, shape] = JSON.parse(sig)
    Promise.all(zs.map((z) => apiPost('cdn-notes', { ...z, ...shape }))).then((rs) => {
      if (!alive) return
      const notes = rs.flatMap((r) => (r.ok && r.d.ok && r.d.notes) || [])
      setGot({ sig, notes: notes.filter((n) => n.block).concat(notes.filter((n) => !n.block)) })
    })
    return () => {
      alive = false
    }
  }, [sig])

  const shown = got.sig === sig ? got.notes : []
  return [...new Map(shown.map((n) => [n.t, n])).values()].map((n) => (
    <WarnCap key={n.t} tone={n.block ? '' : 'gold'} text={n.t} />
  ))
}
