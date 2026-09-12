import { useEffect, useRef, useState } from 'react'
import { T } from '../i18n/fa.js'
import { actAge, actBarPercent, actIsSpinner, actSeen, actWords } from '../lib/acts.js'
import { useActs } from '../state/ActsContext.jsx'

export default function ActionRow({ act }) {
  const { now, cancel, dismiss } = useActs()
  const lastStep = useRef(act ? act.step : null)
  const [stepChanged, setStepChanged] = useState(false)

  useEffect(() => {
    if (!act) return
    if (lastStep.current !== act.step) {
      lastStep.current = act.step
      setStepChanged(true)
    } else {
      setStepChanged(false)
    }
  }, [act])

  if (!act) return null

  const running = act.state === 'run'

  return (
    <div className="arow">
      <span className={'ast ' + act.state}>
        {running ? <span className="apulse" /> : null}
        {T('a_st_' + act.state)}
      </span>
      <span className={'astep' + (stepChanged ? ' sw' : '')}>{actWords(act, now)}</span>
      {running ? <span className="aclock">{actAge(act, now)}</span> : null}
      {running ? (
        act.can ? (
          <button className="abtn danger" type="button" onClick={() => cancel(act.key)}>
            {T('a_cancel')}
          </button>
        ) : null
      ) : (
        <button
          className="abtn"
          type="button"
          title={T('a_dismiss')}
          onClick={() => dismiss(actSeen(act))}
        >
          ✕
        </button>
      )}
      {actIsSpinner(act) ? (
        <div className="abar spin">
          <i />
        </div>
      ) : (
        <div className={'abar' + (running ? '' : ' ' + act.state)}>
          <i style={{ width: actBarPercent(act) + '%' }} />
        </div>
      )}
    </div>
  )
}
