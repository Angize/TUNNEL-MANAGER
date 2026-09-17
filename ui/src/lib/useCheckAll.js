import { useEffect, useRef, useState } from 'react'
import { T } from '../i18n/fa.js'
import { registerCommand } from './pageCommand.js'
import { toast } from './toast.js'

export default function useCheckAll(command, list) {
  const [checking, setChecking] = useState(false)
  const checkRefs = useRef({})
  const wanted = useRef(false)
  const listRef = useRef(list)

  listRef.current = list

  const checkAll = async () => {
    const links = listRef.current || []
    if (!links.length) {
      toast(T('no_tunnel_check'), 'err')
      return
    }
    setChecking(true)
    try {
      await Promise.all(
        links.map((link) => {
          const run = checkRefs.current[link.id]
          return run ? run() : Promise.resolve()
        })
      )
    } finally {
      setChecking(false)
    }
    toast(T('checkall_done'), 'ok')
  }

  const run = useRef(checkAll)
  run.current = checkAll

  useEffect(
    () =>
      registerCommand(command, () => {
        if (listRef.current === null) wanted.current = true
        else run.current()
      }),
    [command]
  )

  useEffect(() => {
    if (!wanted.current || list === null) return
    wanted.current = false
    run.current()
  }, [list])

  return { checking, checkAll, checkRefs }
}
