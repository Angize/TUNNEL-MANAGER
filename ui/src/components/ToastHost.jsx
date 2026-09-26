import { useEffect, useState } from 'react'
import Icon from './Icon.jsx'
import { dismissToast, subscribeToasts } from '../lib/toast.js'

export default function ToastHost() {
  const [items, setItems] = useState([])

  useEffect(() => subscribeToasts(setItems), [])

  return (
    <div className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          className={'toast ' + t.kind + (t.show ? ' show' : '')}
          role={t.kind === 'err' ? 'alert' : undefined}
          onClick={() => dismissToast(t.id)}
        >
          {t.kind === 'ok' ? <Icon name="okc" /> : t.kind === 'err' ? <Icon name="xc" /> : null}
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
