import { useEffect, useState } from 'react'
import { apiGet } from './api.js'

export default function useProxies() {
  const [proxies, setProxies] = useState([])

  useEffect(() => {
    let alive = true
    apiGet('proxies')
      .then((r) => {
        if (alive) setProxies(r.proxies)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  return proxies
}
