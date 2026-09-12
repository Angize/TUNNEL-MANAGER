import { useEffect, useState } from 'react'

const state = {}
const listeners = new Set()

export function getPageQuery(page) {
  return state[page] || ''
}

export function setPageQuery(page, value) {
  state[page] = value
  for (const fn of listeners) fn(state)
}

export default function usePageQuery(page) {
  const [query, setLocal] = useState(() => getPageQuery(page))

  useEffect(() => {
    const fn = () => setLocal(getPageQuery(page))
    listeners.add(fn)
    fn()
    return () => listeners.delete(fn)
  }, [page])

  return [query, (value) => setPageQuery(page, value)]
}
