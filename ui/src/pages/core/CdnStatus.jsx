import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { providerName } from '../../lib/cdn.js'
import { T, TF } from '../../i18n/fa.js'

const ICON = { ok: 'okc', bad: 'warn', wait: 'clock' }
const CHIP = { ok: 'ok', bad: 'bad', wait: 'run' }

function Row({ label, value }) {
  return (
    <span>
      {label}
      <b dir="ltr" className="mono ltrv">
        {value}
      </b>
    </span>
  )
}

export default function CdnStatus({ link, onReload }) {
  const [busy, setBusy] = useState(false)
  const cdn = link.cdn
  if (!cdn) return null
  const tone = cdn.ok ? 'ok' : cdn.error ? 'bad' : 'wait'
  const live = cdn.applied && cdn.applied.ip && cdn.applied.ip !== cdn.ip ? cdn.applied.ip : ''

  const sync = async () => {
    setBusy(true)
    const r = await apiPost('cdn-sync', { id: link.id })
    setBusy(false)
    if (r.ok && r.d.ok) toast(T('cdn_synced'), 'ok')
    else toast(postError(r), 'err')
    onReload()
  }

  return (
    <div className={'cdnown ' + tone}>
      <div className="cdnownh">
        <span className="cdnowni">
          <Icon name={ICON[tone]} />
        </span>
        <b>{TF('cdn_own_t', { p: providerName(cdn.provider) })}</b>
        <span className={'cdnchip ' + CHIP[tone]}>{T('cdn_own_' + tone)}</span>
      </div>
      <div className="cdnownrows">
        <Row label={T('cdn_own_host')} value={cdn.host} />
        <Row label={T('cdn_own_ip')} value={cdn.ip} />
        {cdn.port ? <Row label={T('cdn_own_port')} value={cdn.port} /> : null}
        {cdn.share ? <span>{T('cdn_own_shared')}</span> : null}
      </div>
      {tone === 'bad' ? (
        <>
          <div className="cdnowntx">
            <div>{translateError(cdn.error)}</div>
            <div className="muted">{[live ? TF('cdn_own_live', { ip: live }) : '', T('cdn_own_auto')].filter(Boolean).join(' ')}</div>
          </div>
          <button type="button" className="ghost tone tone-renew cdnfix" disabled={busy} onClick={sync}>
            <Icon name="redo" />
            {T(busy ? 'cdn_syncing' : 'cdn_retry')}
          </button>
        </>
      ) : null}
    </div>
  )
}
