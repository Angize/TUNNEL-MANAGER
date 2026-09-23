import { useEffect, useRef } from 'react'
import { T } from '../i18n/fa.js'
import { registerCommand } from './pageCommand.js'
import { toast } from './toast.js'

export default function useCheckAll(command, list) {
  const actRefs = useRef({})
  const wanted = useRef(false)
  const listRef = useRef(list)
  const checkAll = useRef(null)

  listRef.current = list
  checkAll.current = async () => {
    const links = listRef.current || []
    if (!links.length) {
      toast(T('no_tunnel_check'), 'err')
      return
    }
    await Promise.all(
      links.map((link) => {
        const run = actRefs.current[link.id]
        return run ? run('ping') : Promise.resolve()
      })
    )
    toast(T('checkall_done'), 'ok')
  }

  useEffect(
    () =>
      registerCommand(command, () => {
        if (listRef.current === null) wanted.current = true
        else checkAll.current()
      }),
    [command]
  )

  useEffect(() => {
    if (!wanted.current || list === null) return
    wanted.current = false
    checkAll.current()
  }, [list])

  return actRefs
}
