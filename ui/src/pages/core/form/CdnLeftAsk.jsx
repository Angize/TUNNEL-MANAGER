import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from '../../../components/Icon.jsx'
import { WarnCap } from './controls.jsx'
import { apiPost } from '../../../lib/api.js'
import { postError } from '../../../lib/errors.js'
import { restoreFocus, trapTab } from '../../../lib/focusTrap.js'
import { gsap, reducedMotion } from '../../../lib/motion.js'
import { toast } from '../../../lib/toast.js'
import { providerName } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

export default function CdnLeftAsk({ hosts, onBack, onClosed }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const box = useRef(null)
  const safe = useRef(null)
  const many = hosts.length > 1

  useEffect(() => {
    const opener = document.activeElement
    return () => restoreFocus(opener)
  }, [])

  useLayoutEffect(() => {
    if (safe.current) safe.current.focus()
    if (!box.current || reducedMotion()) return
    gsap.fromTo(
      box.current,
      { opacity: 0, scale: 0.96 },
      { opacity: 1, scale: 1, duration: 0.2, ease: 'ease-out', clearProps: 'transform,opacity' }
    )
  }, [])

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'Escape' || busy) return
      e.stopImmediatePropagation()
      onBack()
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [busy, onBack])

  const drop = async () => {
    setBusy(true)
    setError('')
    const r = await apiPost('cdn-drop', { hosts: hosts.map((h) => h.host) })
    if (!(r.ok && r.d.ok)) {
      setBusy(false)
      setError(postError(r))
      return
    }
    const failed = r.d.failed || []
    if (failed.length) {
      toast(TF('cdn_drop_some', { h: failed.map((f) => f.host).join('، ') }), 'err')
    }
    onClosed()
  }

  return createPortal(
    <div
      className="modalov dlgov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onBack()
      }}
    >
      <div
        className="modal cdnask"
        ref={box}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="cdnaskt"
        tabIndex={-1}
        onKeyDown={(e) => trapTab(e, box.current)}
      >
        <div className="mtext">
          <b className="cdnaskt" id="cdnaskt">
            {T('cdn_left_t')}
          </b>
          <span className="cdnasks">{T(many ? 'cdn_left_many' : 'cdn_left_one')}</span>
        </div>
        <ul className="cdnaskl">
          {hosts.map((h) => (
            <li key={h.host}>
              <span className="mono" dir="ltr">
                {h.host}
              </span>
              <small>{providerName(h.provider)}</small>
            </li>
          ))}
        </ul>
        <div className="cdnaskn">{T(many ? 'cdn_left_keep_many' : 'cdn_left_keep_one')}</div>
        {error ? <WarnCap text={error} /> : null}
        <div className="cdnaskb">
          <button type="button" className="primary danger" disabled={busy} onClick={drop}>
            {busy ? <span className="bspin sm" /> : <Icon name="trash" />}
            {T(busy ? 'cdn_dropping' : many ? 'cdn_drop_many' : 'cdn_drop_one')}
          </button>
          <button type="button" className="ghost" disabled={busy} onClick={onClosed}>
            <Icon name="check" />
            {T(many ? 'cdn_keep_many' : 'cdn_keep_one')}
          </button>
          <button type="button" ref={safe} className="cdnback" disabled={busy} onClick={onBack}>
            {T('cdn_back_form')}
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}
