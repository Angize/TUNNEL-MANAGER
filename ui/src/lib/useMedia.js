import { useEffect, useState } from 'react'

export default function useMedia(query) {
  const [match, setMatch] = useState(() => !!(window.matchMedia && window.matchMedia(query).matches))

  useEffect(() => {
    if (!window.matchMedia) return undefined
    const list = window.matchMedia(query)
    const update = () => setMatch(list.matches)
    update()
    list.addEventListener('change', update)
    return () => list.removeEventListener('change', update)
  }, [query])

  return match
}
