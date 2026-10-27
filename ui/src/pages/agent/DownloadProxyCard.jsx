import { useCallback, useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Select from '../../components/Select.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import { proxyItems } from '../../components/ProxyFields.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { checkable } from '../../lib/keys.js'
import KnobCheck from '../../components/KnobCheck.jsx'

export default function DownloadProxyCard() {
  const [proxies, setProxies] = useState([])
  const [value, setValue] = useState(null)
  const [error, setError] = useState('')
  const [pxPart, setPxPart] = useState(0)
  const [stPart, setStPart] = useState(0)
  const [busy, setBusy] = useState(false)
  const inflight = useRef(false)

  const load = useCallback(async () => {
    setError('')
    setPxPart(0)
    setStPart(0)
    try {
      const [px, s] = await Promise.all([apiGet('proxies', setPxPart), apiGet('settings', setStPart)])
      setProxies(px.proxies)
      setValue({ on: !!s.dl_proxy_on, id: String(s.dl_proxy_id || '') })
    } catch (e) {
      setError(readError(e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const items = proxyItems(proxies)
  const ready = !!value && items.length > 0
  const loading = value === null && !error
  const picked = ready ? value.id || items[0].v : ''

  const commit = async (next) => {
    if (inflight.current) return
    inflight.current = true
    const was = value
    setValue(next)
    setBusy(true)
    const r = await apiPost('settings-set', { dl_proxy_on: next.on, dl_proxy_id: next.on ? next.id : '' })
    inflight.current = false
    setBusy(false)
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      return
    }
    setValue(was)
    toast(postError(r), 'err')
  }

  return (
    <div className="card opc sc-conn dlpx">
      <div className="ophd">
        <span className="sgt">
          <Icon name="shield" />
        </span>
        <div className="hd2">
          <b>{T('dlpx_title')}</b>
          <small>{T('dlpx_sub')}</small>
        </div>
        {ready ? (
          <div
            className={'tglsw' + (value.on ? ' on' : '') + (busy ? ' dis' : '')}
            aria-label={T('dlpx_on')}
            aria-busy={busy}
            aria-disabled={busy ? 'true' : undefined}
            {...checkable('switch', value.on, () => commit({ on: !value.on, id: picked }))}
          >
            <KnobCheck on={value.on} />
          </div>
        ) : null}
      </div>
      <LoadBar on={loading} value={(pxPart + stPart) / 2} />
      {ready ? (
        <div className="oprow" aria-busy={busy}>
          <div className={'opsel' + (value.on ? '' : ' off') + (busy ? ' busy' : '')} inert={!value.on}>
            <Select items={items} value={picked} onChange={(id) => id !== picked && commit({ on: true, id })} />
          </div>
        </div>
      ) : loading ? null : value ? (
        <div className="muted" style={{ fontSize: 12 }}>
          {T('dlpx_none')}
        </div>
      ) : error ? (
        <div className="msg loadfail">
          <span>{T('dlpx_load_fail') + ' ' + error}</span>
          <button type="button" className="ghost" onClick={load}>
            <Icon name="redo" />
            {T('retry')}
          </button>
        </div>
      ) : null}
    </div>
  )
}
