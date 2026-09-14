import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from '../../components/Icon.jsx'
import { T, TF } from '../../i18n/fa.js'

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

export default function SaveDock({ count, busy, onRevert, onSave }) {
  const phone = usePhone()

  useEffect(() => {
    if (!phone) return undefined
    document.body.classList.add('dock-on')
    return () => document.body.classList.remove('dock-on')
  }, [phone])

  const bar = (
    <div className={'savedock' + (phone ? ' docked' : '')} role="region" aria-label={T('save')}>
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
