import { T } from '../i18n/fa.js'
import { toast } from '../lib/toast.js'
import { pressable } from '../lib/keys.js'

function copyFallback(text) {
  try {
    const area = document.createElement('textarea')
    area.value = text
    area.setAttribute('readonly', '')
    area.style.cssText = 'position:fixed;top:0;left:-9999px;opacity:0'
    document.body.appendChild(area)
    area.select()
    area.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    area.remove()
    return !!ok
  } catch {
    return false
  }
}

export function copyText(text, event) {
  if (event) event.stopPropagation()
  const value = String(text || '').trim()
  if (!value) return
  const done = (ok) => toast(ok ? T('copied') : T('copy_fail'), ok ? 'ok' : 'err')
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(value).then(
      () => done(true),
      () => done(copyFallback(value))
    )
    return
  }
  done(copyFallback(value))
}

export default function CopyValue({ text, className }) {
  const value = String(text || '')
  if (!value) return <b className="mono">—</b>
  return (
    <b
      className={'mono cpv' + (className ? ' ' + className : '')}
      title={T('tip_copy')}
      {...pressable((e) => copyText(value, e))}
    >
      {value}
    </b>
  )
}
