import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from '../../components/Icon.jsx'
import { T, TF } from '../../i18n/fa.js'
import usePresence from '../../lib/usePresence.js'

const EXIT_MS = 180

const PHONE = '(max-width: 840px)'

function usePhone() {
  const [phone, setPhone] = useState(() => !!(window.matchMedia && window.matchMedia(PHONE).matches))

  useEffect(() => {
    if (!window.matchMedia) return undefined
    const query = window.matchMedia(PHONE)
    const update = () => setPhone(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  return phone
}

function Bar({ count, busy, leaving, onRevert, onSave }) {
  const phone = usePhone()

  useEffect(() => {
    if (!phone || leaving) return undefined
    document.body.classList.add('dock-on')
    return () => document.body.classList.remove('dock-on')
  }, [phone, leaving])

  const bar = (
    <div
      className={'savedock' + (phone ? ' docked' : '') + (leaving ? ' out' : '')}
      role="region"
      aria-label={T('save')}
      inert={leaving}
    >
      <span className="sdtext">
        <i />
        {TF('set_dirty', { n: count })}
      </span>
      <button type="button" className="ghost" onClick={onRevert} disabled={busy}>
        <Icon name="undo" />
        {T('set_revert')}
      </button>
      <button type="button" className="primary" onClick={onSave} disabled={busy}>
        <Icon name="check" />
        {busy ? T('saving') : T('save')}
      </button>
    </div>
  )

  return phone ? createPortal(bar, document.body) : bar
}

export default function SaveDock({ show, count, busy, onRevert, onSave }) {
  const shown = usePresence(show, EXIT_MS)
  const [kept, setKept] = useState(count)
  if (show && count !== kept) setKept(count)
  if (!shown) return null
  return <Bar count={show ? count : kept} busy={busy} leaving={!show} onRevert={onRevert} onSave={onSave} />
}
