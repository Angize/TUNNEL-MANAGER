import { useCallback, useEffect, useRef, useState } from 'react'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'

const SAVE_DEBOUNCE = 350

function toMap(list) {
  const map = {}
  for (const key of list) map[key] = 1
  return map
}

export default function useHiddenTypes({ evTypes, onSaved }) {
  const [hidden, setHidden] = useState({})
  const [known, setKnown] = useState(false)
  const current = useRef({})
  const server = useRef([])
  const saving = useRef(false)
  const dirty = useRef(false)
  const timer = useRef(0)
  const evTypesRef = useRef(evTypes)
  const onSavedRef = useRef(onSaved)

  evTypesRef.current = evTypes
  onSavedRef.current = onSaved

  useEffect(() => () => clearTimeout(timer.current), [])

  const publish = useCallback((map) => {
    current.current = map
    setHidden(map)
  }, [])

  const isPending = useCallback(() => saving.current || dirty.current || !!timer.current, [])

  const orderedList = useCallback(
    () => evTypesRef.current.filter(([key]) => current.current[key]).map(([key]) => key),
    []
  )

  const saveNow = useCallback(async () => {
    if (saving.current) return
    saving.current = true
    while (dirty.current) {
      dirty.current = false
      const list = orderedList()
      const r = await apiPost('settings-set', { log_hidden: list })
      if (!(r.ok && r.d.ok)) {
        dirty.current = false
        publish(toMap(server.current))
        saving.current = false
        toast(postError(r), 'err')
        return
      }
      server.current = list
    }
    saving.current = false
    onSavedRef.current()
  }, [orderedList, publish])

  const scheduleSave = useCallback(() => {
    dirty.current = true
    clearTimeout(timer.current)
    timer.current = setTimeout(() => {
      timer.current = 0
      saveNow()
    }, SAVE_DEBOUNCE)
  }, [saveNow])

  const adoptFromServer = useCallback(
    (list) => {
      if (isPending()) return
      server.current = (list || []).slice()
      publish(toMap(server.current))
      setKnown(true)
    },
    [isPending, publish]
  )

  const toggleType = useCallback(
    (key) => {
      const next = { ...current.current }
      if (next[key]) delete next[key]
      else next[key] = 1
      publish(next)
      scheduleSave()
    },
    [publish, scheduleSave]
  )

  const toggleGroup = useCallback(
    (group) => {
      const rows = evTypesRef.current.filter(([, g]) => g === group)
      const hideAll = rows.every(([key]) => !current.current[key])
      const next = { ...current.current }
      for (const [key] of rows) {
        if (hideAll) next[key] = 1
        else delete next[key]
      }
      publish(next)
      scheduleSave()
    },
    [publish, scheduleSave]
  )

  return {
    hidden,
    hiddenCount: Object.keys(hidden).length,
    known,
    adoptFromServer,
    isPending,
    toggleType,
    toggleGroup,
  }
}
