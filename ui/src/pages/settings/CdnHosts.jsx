import { useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { ActionButton } from '../core/form/HealthRow.jsx'
import useFlipList from '../../lib/useFlipList.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { providerName } from '../../lib/cdn.js'
import { T, TF } from '../../i18n/fa.js'
import '../core/coreform.css'

function madeWhen(ts) {
  if (!ts) return ''
  return new Date(ts * 1000).toLocaleString('fa-IR-u-nu-latn', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function CdnHosts({ hosts, onStatus }) {
  const [going, setGoing] = useState('')
  const list = useRef(null)
  const rows = (hosts || []).filter((h) => !h.link)
  useFlipList(list, rows.map((h) => h.host), 'cdnhosts')

  const drop = async (h) => {
    if (!(await confirmBox(TF('cdn_drop_ask', { h: h.host, p: providerName(h.provider) }), T('cdn_drop_yes')))) return
    setGoing(h.host)
    const r = await apiPost('cdn-drop', { hosts: [h.host] })
    setGoing('')
    if (!(r.ok && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    const failed = (r.d.failed || [])[0]
    if (failed) toast(failed.error, 'err')
    else toast(TF('cdn_dropped', { h: h.host }), 'ok')
    onStatus()
  }

  return (
    <div className="card opc sc-panel apcard cdnhosts">
      <div className="ophd">
        <span className="sgt cdnhostsi">
          <Icon name="globe" />
        </span>
        <div className="hd2">
          <b>{T('cdn_hosts_t')}</b>
          <small>{T('cdn_hosts_d')}</small>
        </div>
        <span className={'cdnchip ' + (rows.length ? 'warn' : 'ok')}>
          {rows.length ? TF('cdn_hosts_n', { n: rows.length }) : T('cdn_hosts_zero')}
        </span>
      </div>
      <div className="cdnhostl" ref={list}>
        {rows.map((h) => (
          <div key={h.host} className="erow warn">
            <span className="estat warn">
              <Icon name="warn" />
            </span>
            <span className="cdnhostc">
              <span className="eip" dir="ltr" title={h.host}>
                {h.host}
              </span>
              <span className="cdnhostm">{[providerName(h.provider), madeWhen(h.made)].filter(Boolean).join(' · ')}</span>
            </span>
            <span className="eacts">
              <ActionButton
                icon="trash"
                tone="del"
                title={T('cdn_drop_btn')}
                spinning={going === h.host}
                disabled={!!going}
                onClick={() => drop(h)}
              />
            </span>
          </div>
        ))}
      </div>
      <div className="cdnused">{T(rows.length ? 'cdn_hosts_reuse' : 'cdn_hosts_none')}</div>
    </div>
  )
}
