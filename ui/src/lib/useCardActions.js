import { useEffect, useRef } from 'react'
import { apiPost } from './api.js'
import { postError, translateError } from './errors.js'
import { askBox } from './dialog.js'
import { toast } from './toast.js'
import { sideText } from '../pages/tunnels/sideHealth.js'
import { T } from '../i18n/fa.js'

export default function useCardActions({ link, onReload, setMessage, withBusy, withToggle, pickRebuild, register }) {
  const setEnabled = (next, quiet) =>
    withToggle('toggle', async () => {
      const r = await apiPost('link-toggle', { id: link.id, enabled: next })
      const err = r.ok && r.d.ok ? '' : postError(r)
      if (!quiet) toast(err || T(next ? 'turned_on' : 'turned_off'), err ? 'err' : 'ok')
      await onReload()
      return err
    })

  const check = async () => {
    const r = await withBusy('ping', () => {
      setMessage({ cls: '', text: T('checking_conn') })
      return apiPost('check-link', { id: link.id })
    })
    if (!r) return undefined
    if (!(r.ok && r.d.ok)) {
      setMessage({ cls: 'err', text: postError(r) })
      return 'bad'
    }
    if (link.enabled === false) {
      setMessage({ cls: '', text: T('conn_off') })
      return 'off'
    }
    const d = r.d
    const aUp = d.a_online && d.a_health && d.a_health.up
    const bUp = d.b_online && d.b_health && d.b_health.up
    const allOk = aUp && bUp && d.a_health.alive === true && d.b_health.alive === true
    setMessage({
      cls: allOk ? 'ok' : 'err',
      lines: {
        ok: allOk,
        head: allOk ? T('conn_ok') : T('conn_bad'),
        a: (link.a_name || 'A') + ': ' + sideText(d.a_online, d.a_health, translateError(d.a_error)),
        b: (link.b_name || 'B') + ': ' + sideText(d.b_online, d.b_health, translateError(d.b_error)),
      },
    })
    return allOk ? 'ok' : 'bad'
  }

  const reset = async (quiet) => {
    const r = await withBusy('reset', () => apiPost('traffic-reset', { id: link.id }))
    if (!r) return undefined
    const err = r.ok && r.d.ok ? '' : postError(r)
    if (!quiet) toast(err || T('t_reset_done'), err ? 'err' : 'ok')
    if (!err) onReload()
    return err
  }

  const startAct = async (key, failKey, quiet) => {
    const r = await withBusy(key, () => apiPost(key + '-link', { id: link.id }))
    if (!r) return undefined
    if (!(r.ok && r.d.act)) {
      const err = postError(r, failKey)
      if (!quiet) toast(err, 'err')
      return { err }
    }
    setMessage(null)
    onReload()
    return { act: r.d.act }
  }

  const bulk = useRef(null)
  bulk.current = {
    ping: check,
    reset: () => reset(true),
    toggle: (next) => setEnabled(next, true),
    restart: () => startAct('restart', 'restart_failed', true),
    rebuild: () => (link.drift ? Promise.resolve({ err: T('bulk_drift') }) : startAct('rebuild', 'rebuild_failed', true)),
  }

  useEffect(() => {
    if (register) register((name, arg) => bulk.current[name](arg))
  }, [register])

  return {
    check,
    toggle: (e) => {
      e.stopPropagation()
      setEnabled(link.enabled === false, false)
    },
    resetTraffic: async () => {
      if (await askBox(T('reset_confirm'), T('reset_yes'))) await reset(false)
    },
    restart: async () => {
      if (await askBox(T('restart_confirm'), T('restart_yes'))) await startAct('restart', 'restart_failed', false)
    },
    rebuild: async () => {
      if (link.drift) {
        pickRebuild()
        return
      }
      if (await askBox(T('rebuild_confirm'), T('tip_rebuild'))) await startAct('rebuild', 'rebuild_failed', false)
    },
  }
}
