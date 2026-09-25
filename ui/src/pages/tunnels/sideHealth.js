import { T } from '../../i18n/fa.js'

export function formatMs(value) {
  return (value >= 10 ? Math.round(value) : Math.round(value * 10) / 10) + 'ms'
}

export function pingInfo(health) {
  if (!health) return ''
  const parts = []
  if (health.rtt_ms != null) parts.push(T('t_ping') + ' ' + formatMs(health.rtt_ms))
  if (health.loss_pct != null && health.loss_pct > 0) {
    parts.push(T('t_loss') + ' ' + Math.round(health.loss_pct) + T('pct'))
  }
  return parts.join(' · ')
}

export function sideState(online, health) {
  if (!online) return { kind: 'bad', word: T('st_disc'), title: T('t_side_off') }
  if (!health) return { kind: 'bad', word: T('st_disc'), title: T('t_side_notun') }
  if (health.up == null) return { kind: 'na', word: '…', title: T('checking') }
  if (!health.up) return { kind: 'bad', word: T('st_disc'), title: T('t_side_ifdown') }
  if (health.alive === true) return { kind: 'ok', word: '', title: T('tst_connected') }
  if (health.alive === false) return { kind: 'bad', word: T('st_disc'), title: T('tst_dead') }
  return { kind: 'na', word: '…', title: T('checking') }
}

export function linkSideState(link, side) {
  if (link.enabled === false) return { kind: 'na', word: T('st_off'), title: T('st_off'), off: true }
  if (link.building && !link[side + '_health']) return { kind: 'na', word: '…', title: T('checking') }
  return sideState(link[side + '_online'], link[side + '_health'])
}

export function sideText(online, health, err) {
  if (!online) return T('t_side_off')
  if (!health) return err ? T('t_side_err') + ' ' + err : T('t_side_notun')
  if (health.up == null) return T('checking')
  if (!health.up) return T('t_side_ifdown')
  if (health.alive === true) {
    const extra = pingInfo(health)
    return T('t_side_conn') + (extra ? ' · ' + extra : '')
  }
  if (health.alive === false) {
    return (
      T('t_side_nopingr') +
      (health.loss_pct != null
        ? ' (' + T('t_loss') + ' ' + Math.round(health.loss_pct) + T('pct') + ')'
        : '')
    )
  }
  return T('t_side_up_unk')
}
