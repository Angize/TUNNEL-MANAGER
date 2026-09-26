import { useRef } from 'react'
import Reveal from './Reveal.jsx'
import { T } from '../i18n/fa.js'
import { actAge, actBarPercent, actIsSpinner, actSeen, actWords } from '../lib/acts.js'
import { useActs } from '../state/ActsContext.jsx'

function Row({ act }) {
  const { now, cancel, dismiss } = useActs()
  const firstStep = useRef(act.step)
  const running = act.state === 'run'

  return (
    <div className="arow">
      <span className={'ast ' + act.state}>
        {running ? <span className="apulse" /> : null}
        {T('a_st_' + act.state)}
      </span>
      <span key={act.step} className={'astep' + (act.step !== firstStep.current ? ' sw' : '')}>
        {actWords(act, now)}
      </span>
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

export default function ActionRow({ act }) {
  return <Reveal show={!!act}>{act ? <Row act={act} /> : null}</Reveal>
}
