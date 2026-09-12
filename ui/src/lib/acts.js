import { T } from '../i18n/fa.js'
import { translateError } from './errors.js'
import { num } from './num.js'

export function actSeen(act) {
  return act.key + ':' + act.ended
}

export function actAge(act, now) {
  const seconds =
    act.state === 'run' ? now - num(act.started) : num(act.ended || now) - num(act.started)
  const total = Math.max(0, num(seconds))
  const m = Math.floor(total / 60)
  const s = total % 60
  return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s
}

export function actWords(act, now) {
  if (act.state === 'fail') return translateError(act.err) || T('a_st_fail')
  if (act.state === 'cancel') return T('a_stopped')
  if (act.state === 'done') {
    return act.note ? translateError(act.note) : T('a_took').replace('{t}', actAge(act, now))
  }
  return act.step || T('a_working')
}

export function actBarPercent(act) {
  if (act.state === 'done') return 100
  return Math.max(5, num(act.pct))
}

export function actIsSpinner(act) {
  return act.state === 'run' && !num(act.sn)
}
