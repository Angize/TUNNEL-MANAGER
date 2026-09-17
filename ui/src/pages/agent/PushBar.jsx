import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

export function pushWord(status) {
  if (status.state === 'wait') return T('ag_p_wait')
  if (status.state === 'skip') return T('ag_p_skip')
  if (status.state === 'same') return T('ag_p_same')
  if (status.state === 'ok') return T('ag_p_ok')
  if (status.state === 'err') return T('upe_' + (status.err || 'failed'))
  if (!status.step) return T('ag_p_wait')
  const word = T('ups_' + status.step)
  if (num(status.sn) > 1) {
    return (
      word +
      ' · ' +
      T('ups_of').replace('{i}', num(status.si)).replace('{n}', num(status.sn))
    )
  }
  return word
}

export function pushLabel(status) {
  let text = pushWord(status)
  if (status.state === 'ok' && num(status.restarted) > 0) {
    text += ' · ' + T('ups_restarted').replace('{n}', num(status.restarted))
  }
  if (num(status.failed) > 0) {
    text += ' · ' + T('ups_failed_n').replace('{n}', num(status.failed))
  }
  return text
}

export function pushTone(status) {
  if (status.state === 'err') return 'err'
  if (status.state === 'ok' || status.state === 'same') return 'ok'
  return ''
}

export default function PushBar({ status }) {
  const pct = Math.max(0, Math.min(100, num(status.pct)))
  const tone = pushTone(status)
  const spin = status.state === 'run' && status.remote
  return (
    <>
      <div className={'pushbar' + (tone ? ' ' + tone : '') + (spin ? ' spin' : '')}>
        <i style={{ width: pct + '%' }} />
      </div>
      <div className="plbl" title={status.detail || undefined}>
        <span>{pushLabel(status)}</span>
        <b>{pct}%</b>
      </div>
    </>
  )
}
