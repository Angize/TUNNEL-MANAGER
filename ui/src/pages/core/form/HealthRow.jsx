import Icon from '../../../components/Icon.jsx'
import { barPercent, countdownText, remain, stepTotal } from './countdown.js'
import { WarnCap } from './controls.jsx'
import { T } from '../../../i18n/fa.js'
import { pressable } from '../../../lib/keys.js'

export const EDGE_TITLES = {
  activeRetry: 'ph_active_retry',
  dead: 'ph_dead',
  suspect: 'ph_suspect',
  active: 'ph_active',
  idle: 'ph_healthy',
}

export const PEER_TITLES = {
  activeRetry: 'peer_st_active_retry',
  dead: 'ph_dead',
  suspect: 'ph_suspect',
  active: 'peer_st_active',
  idle: 'peer_st_rot',
}

export function healthTone(health, active, titles) {
  if (health && health.state === 'dead') {
    return {
      row: 'bad',
      stat: 'bad',
      icon: active ? 'bolt' : 'xc',
      title: T(active ? titles.activeRetry : titles.dead),
    }
  }
  if (health && health.state === 'suspect') {
    return {
      row: 'warn',
      stat: 'warn',
      icon: active ? 'bolt' : 'warn',
      title: T(active ? titles.activeRetry : titles.suspect),
    }
  }
  if (active) return { row: 'ok', stat: 'ok', icon: 'bolt', title: T(titles.active) }
  return { row: 'ok', stat: 'ok', icon: 'okc', title: T(titles.idle) }
}

export function isBurned(health) {
  return !!health && (health.state === 'suspect' || health.state === 'dead')
}

export function Countdown({ health, now, polledMs }) {
  const left = remain(now, polledMs, health.next)
  if (left < 0) return null
  return <span className="pcd">{countdownText(left)}</span>
}

export function ProgressBar({ health, now, polledMs, tuning }) {
  const total = stepTotal(health, tuning)
  const left = remain(now, polledMs, health.next)
  const pct = barPercent(total, left)
  if (pct < 0) return null
  return (
    <span className={'pbar' + (health.state === 'dead' ? ' bad' : '')}>
      <i style={{ width: pct + '%' }} />
    </span>
  )
}

export function Badges({ total, suspect, dead }) {
  return (
    <>
      <span className="pbadge ok">{total - suspect - dead + ' ' + T('pb_healthy')}</span>
      {suspect ? <span className="pbadge warn">{suspect + ' ' + T('pb_temp')}</span> : null}
      {dead ? <span className="pbadge bad">{dead + ' ' + T('pb_dead')}</span> : null}
    </>
  )
}

export function StaleCap({ status }) {
  return (
    <WarnCap
      text={status.stale ? T(status.polledMs ? 'live_stale' : 'live_unread') + ' — ' + status.why : ''}
      style={{ marginBottom: 8 }}
    />
  )
}

export function Accordion({ label, badges, collapsible, open, onToggle, children }) {
  return (
    <div className="pacc">
      <div
        className="pacchd"
        style={collapsible ? undefined : { cursor: 'default' }}
        {...(collapsible ? pressable(onToggle) : {})}
      >
        <div className="pacctl">
          <div className="pacct">{label}</div>
          <div className="paccs">{badges}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {collapsible ? <div className={'pchev' + (open ? ' open' : '')}>▾</div> : null}
        </div>
      </div>
      <div className="paccbody" style={open ? undefined : { display: 'none' }}>
        {children}
      </div>
    </div>
  )
}

export function ActionButton({ title, tone, spinning, disabled, icon, onClick }) {
  return (
    <button
      type="button"
      className={'eib' + (tone ? ' ' + tone : '')}
      title={title}
      disabled={disabled}
      style={disabled ? { opacity: 0.45, pointerEvents: 'none' } : undefined}
      onClick={onClick}
    >
      {spinning ? <span className="bspin" /> : <Icon name={icon} />}
    </button>
  )
}
