import { useRef } from 'react'
import Reveal from './Reveal.jsx'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'
import { actAge, actBarPercent, actIsSpinner, actSeen, actWords } from '../lib/acts.js'
import { useActs } from '../state/ActsContext.jsx'

const CDN_ICON = { ok: 'okc', undo: 'undo', info: 'info' }

export function CdnSteps({ steps }) {
  if (!steps || !steps.length) return null
  return (
    <ol className="cdnsteps">
      {steps.map((s, i) => (
        <li key={i} className={s.st}>
          <Icon name={CDN_ICON[s.st] || 'info'} />
          <span>{s.t}</span>
          {s.st === 'undo' ? <small>{T('cdn_undone')}</small> : null}
        </li>
      ))}
    </ol>
  )
}

function Row({ act, warn }) {
  const { now, cancel, dismiss } = useActs()
  const firstStep = useRef(act.step)
  const running = act.state === 'run'
  const tone = warn && act.state === 'done' && act.note ? 'warn' : act.state

  return (
    <div className="arow">
      <span className={'ast ' + tone}>
        {running ? <span className="apulse" /> : null}
        {T('a_st_' + tone)}
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
        <div className={'abar' + (running ? '' : ' ' + tone)}>
          <i style={{ width: actBarPercent(act) + '%' }} />
        </div>
      )}
    </div>
  )
}

export default function ActionRow({ act, warn }) {
  return (
    <Reveal show={!!act}>
      {act ? <Row act={act} warn={warn} /> : null}
      {act ? <CdnSteps steps={act.cdn} /> : null}
    </Reveal>
  )
}
