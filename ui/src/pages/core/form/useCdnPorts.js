import { useEffect, useState } from 'react'
import { apiPost } from '../../../lib/api.js'

export default function useCdnPorts(ask) {
  const sig = ask ? JSON.stringify(ask) : ''
  const [got, setGot] = useState({ sig: '', info: null })

  useEffect(() => {
    if (!sig) return undefined
    let alive = true
    apiPost('cdn-ports', JSON.parse(sig)).then((r) => {
      if (alive) setGot({ sig, info: r.ok && r.d.ok ? r.d : null })
    })
    return () => {
      alive = false
    }
  }, [sig])

  return sig && got.sig === sig ? got.info : null
}
