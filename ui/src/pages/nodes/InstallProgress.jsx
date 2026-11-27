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
      <button type="button" className="ghost tone tone-renew" disabled={busy} aria-busy={busy} onClick={run}>
        {busy ? <span className="bspin ink sm" /> : <Icon name="token" />}
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
  const bannerText = running ? state.steps[at - 1]?.label || T('inst_ssh') : state.error || state.banner
  const shownSteps = running ? [] : state.steps.filter(step => step.state === 'err' || step.state === 'warn')

  return <InstallReport
    tone={running ? 'run' : state.success ? 'ok' : 'err'}
    banner={bannerText}
    counter={running && total > 0 ? TF('inst_step_of', { n: at, total }) : null}
    steps={shownSteps}
    onForgetKey={state.hostkey ? onForgetKey : undefined}
  />
}

export function InstallReport({ tone, banner, counter, steps = [], onForgetKey }) {
  return (
    <div className="iwrap">
      <div className={'ibanner ' + tone} role={tone === 'err' ? 'alert' : 'status'}>
        {tone === 'run' ? <span className="ispin" /> : tone === 'ok' ? <Check /> : <Cross />}
        <Roll text={banner} />
        {counter && <span className="ibx">{counter}</span>}
      </div>
      {steps.map(step => (
        <div className={'istep ' + step.state} key={step.key || step.label}>
          <StepIcon state={step.state} />
          <div className="istep-b">
            <div className="istep-t">{step.label || ''}</div>
            {step.detail ? <div className="istep-s">{step.detail}</div> : null}
            {step.state === 'err' && step.log ? <div className="ilog">{step.log}</div> : null}
            {step.state === 'err' && onForgetKey ? <HostKeyFix onFix={onForgetKey} /> : null}
          </div>
        </div>
      ))}
    </div>
  )
}
