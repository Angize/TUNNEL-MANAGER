import { useRef } from 'react'
import { FA, T, TF } from '../../i18n/fa.js'
import { translateError } from '../../lib/errors.js'
import { num } from '../../lib/num.js'

function errWord(status) {
  const key = 'upe_' + status.err
  const why = status.detail ? translateError(status.detail) : ''
  if (!(key in FA)) return why || T('upe_failed')
  return why ? T(key) + ' — ' + why : T(key)
}

function pushWord(status) {
  if (status.state === 'wait') return T('ag_p_wait')
  if (status.state === 'skip') return T('ag_p_skip')
  if (status.state === 'same') return T('ag_p_same')
  if (status.state === 'ok') return T('ag_p_ok')
  if (status.state === 'err') return errWord(status)
  const word = T('ups_' + status.step)
  if (num(status.sn) > 1) {
    return word + ' · ' + TF('ups_of', { i: num(status.si), n: num(status.sn) })
  }
  return word
}

function pushLabel(status) {
  let text = pushWord(status)
  if (status.state === 'ok' && num(status.restarted) > 0) {
    text += ' · ' + TF('ups_restarted', { n: num(status.restarted) })
  }
  if (num(status.failed) > 0) {
    text += ' · ' + TF('ups_failed_n', { n: num(status.failed) })
  }
  return text
}

export function pushTone(status) {
  if (status.state === 'err') return 'err'
  if (status.state === 'ok' || status.state === 'same') return 'ok'
  return ''
}

export default function PushBar({ status }) {
  const pct = num(status.pct)
  const tone = pushTone(status)
  const spin = status.state === 'run' && status.remote
  const step = status.state + ':' + status.step + ':' + status.si
  const firstStep = useRef(step)
  return (
    <>
      <div className={'pushbar' + (tone ? ' ' + tone : '') + (spin ? ' spin' : '')}>
        <i style={{ width: pct + '%' }} />
      </div>
      <div className="plbl" title={status.detail || undefined}>
        <span key={step} className={step !== firstStep.current ? 'sw' : undefined}>
          {pushLabel(status)}
        </span>
        {status.state === 'run' || status.state === 'wait' ? <b>{pct}%</b> : null}
      </div>
    </>
  )
}
