import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import { T, TF } from '../../i18n/fa.js'

export function StepIcon({ state }) {
  if (state === 'ok') return <span className="istep-i ok"><Check /></span>
  if (state === 'err') return <span className="istep-i err"><Cross /></span>
  if (state === 'warn') return <span className="istep-i warn"><Icon name="warn" /></span>
  if (state === 'run') return <span className="istep-i run"><span className="ispin" /></span>
  return <span className="istep-i wait" />
}

function displayState(confirmed, running) {
  if (confirmed === 'ok' || confirmed === 'warn' || confirmed === 'err') return confirmed
  return running ? 'run' : 'err'
}

export function Roll({ text }) {
  const [now, setNow] = useState(text)
  const [gone, setGone] = useState(null)
  if (text !== now) {
    setGone(now)
    setNow(text)
  }
  return (
    <span className="iroll">
      {gone !== null ? (
        <span key={'out' + gone} className="irl out" aria-hidden="true" onAnimationEnd={() => setGone(null)}>
          {gone}
        </span>
      ) : null}
      <span key={now} className={'irl' + (gone !== null ? ' in' : '')}>
        {now}
      </span>
    </span>
  )
}

export function HostKeyFix({ onFix }) {
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      await onFix()
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="hkfix">
      <button type="button" className="ghost tone tone-renew" disabled={busy} onClick={run}>
        {busy ? <span className="bspin sm" /> : <Icon name="reset" />}
        {T('inst_hostkey_fix')}
      </button>
      <div className="istep-s">{T('inst_hostkey_hint')}</div>
    </div>
  )
}

export default function InstallProgress({ state, onForgetKey }) {
  if (!state) return null

  const running = !state.finished
  const total = state.steps.length
  const at = Math.min(Math.max(state.revealIdx, 1), total)
  const bannerText = running
    ? (state.steps[at - 1] || {}).label || T('inst_installing')
    : state.error || state.banner || T('inst_done')
  const shownSteps = running
    ? []
    : state.steps
        .map((step, i) => ({ step, shown: displayState(state.confirmed[i] || '', false), i }))
        .filter((x, i) => i < state.revealIdx && x.shown !== 'ok')

  return (
    <div className="iwrap">
      <div className={'ibanner ' + (running ? 'run' : state.success ? 'ok' : 'err')}>
        {running ? <span className="ispin" /> : state.success ? <Check /> : <Cross />}
        <Roll text={bannerText} />
        {running ? <span className="ibx">{TF('inst_step_of', { n: at, total })}</span> : null}
      </div>
      {shownSteps.map(({ step, shown, i }) => (
        <div className={'istep ' + shown} key={i}>
          <StepIcon state={shown} />
          <div className="istep-b">
            <div className="istep-t">{step.label || ''}</div>
            {step.detail ? <div className="istep-s">{step.detail}</div> : null}
            {shown === 'err' && step.log ? <div className="ilog">{step.log}</div> : null}
            {shown === 'err' && state.hostkey && onForgetKey ? <HostKeyFix onFix={onForgetKey} /> : null}
          </div>
        </div>
      ))}
    </div>
  )
}
