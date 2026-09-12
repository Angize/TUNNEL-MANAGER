import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import { T } from '../../i18n/fa.js'

function StepIcon({ state }) {
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

export default function InstallProgress({ state }) {
  if (!state) return null

  const running = !state.finished
  const bannerText = running ? T('inst_installing') : state.error || state.banner || T('inst_done')

  return (
    <div className="iwrap">
      <div className={'ibanner ' + (running ? 'run' : state.success ? 'ok' : 'err')}>
        {running ? <span className="ispin" /> : state.success ? <Check /> : <Cross />}
        <span>{bannerText}</span>
      </div>
      {Array.from({ length: state.revealIdx }, (_, i) => {
        const step = state.steps[i] || {}
        const shown = displayState(state.confirmed[i] || '', running)
        return (
          <div className={'istep ' + shown} key={i}>
            <StepIcon state={shown} />
            <div className="istep-b">
              <div className="istep-t">{step.label || ''}</div>
              {step.detail ? <div className="istep-s">{step.detail}</div> : null}
              {shown === 'err' && step.log ? <div className="ilog">{step.log}</div> : null}
            </div>
          </div>
        )
      })}
    </div>
  )
}
