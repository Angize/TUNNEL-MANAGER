import { useEffect, useState } from 'react'
import Icon from './Icon.jsx'
import { subscribeToasts } from '../lib/toast.js'

export default function ToastHost() {
  const [items, setItems] = useState([])

  useEffect(() => subscribeToasts(setItems), [])

  return (
    <div className="toasts">
      {items.map((t) => (
        <div key={t.id} className={'toast ' + t.kind + (t.show ? ' show' : '')}>
          {t.kind === 'ok' ? <Icon name="okc" /> : t.kind === 'err' ? <Icon name="xc" /> : null}
          <span>{t.msg}</span>
        </div>
      ))}
    </div>
  )
}
