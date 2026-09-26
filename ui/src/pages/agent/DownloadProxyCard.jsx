import { useCallback, useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Select from '../../components/Select.jsx'
import { proxyItems } from '../../components/ProxyFields.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { checkable } from '../../lib/keys.js'

export default function DownloadProxyCard() {
  const [proxies, setProxies] = useState([])
  const [value, setValue] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      const [px, s] = await Promise.all([apiGet('proxies'), apiGet('settings')])
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
  const picked = ready ? value.id || items[0].v : ''

  const save = async () => {
    const r = await apiPost('settings-set', {
      dl_proxy_on: value.on,
      dl_proxy_id: value.on ? picked : '',
    })
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      return
    }
    alertBox(postError(r))
  }

  return (
    <div className="card opc sc-conn">
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
            className={'tglsw' + (value.on ? ' on' : '')}
            aria-label={T('dlpx_on')}
            {...checkable('switch', value.on, () => setValue({ on: !value.on, id: picked }))}
          />
        ) : null}
      </div>
      {ready ? (
        <div className="oprow">
          <div className={'opsel' + (value.on ? '' : ' off')} inert={!value.on}>
            <Select items={items} value={picked} onChange={(id) => setValue({ on: true, id })} />
          </div>
          <button type="button" className="primary glass opsave" onClick={save}>
            <Icon name="check" />
            {T('save')}
          </button>
        </div>
      ) : value ? (
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
