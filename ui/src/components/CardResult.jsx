import Icon from './Icon.jsx'
import { Check, Cross } from './Marks.jsx'
import RichText from './RichText.jsx'
import Reveal from './Reveal.jsx'
import { T } from '../i18n/fa.js'

function Body({ message }) {
  if (message.lines) {
    return (
      <>
        <div className="chh">
          {message.lines.ok ? <Check /> : <Cross />} {message.lines.head}
        </div>
        <div className="chl">{message.lines.a}</div>
        <div className="chl">{message.lines.b}</div>
      </>
    )
  }
  if (message.speed) {
    return (
      <>
        <div className="chh">
          {message.cls === 'ok' ? <Check /> : <Cross />} {T('speed_done')}{' '}
          <span className="muted">{message.speed.how}</span>
        </div>
        <div className="chl">
          {T('speed_down')}: {'\u2066' + message.speed.down + '\u2069'}
        </div>
        <div className="chl">
          {T('speed_up')}: {'\u2066' + message.speed.up + '\u2069'}
        </div>
        <div className="wrap muted" style={{ marginTop: 6 }}>
          <RichText text={T('speed_note')} />
        </div>
      </>
    )
  }
  return (
    <>
      {message.swap ? <Icon name="swap" /> : null}
      {message.text}
    </>
  )
}

export default function CardResult({ message }) {
  return (
    <Reveal show={!!message}>
      <div className={'msg' + (message && message.cls ? ' ' + message.cls : '')}>
        {message ? (
          <div className="mres" key={JSON.stringify(message)}>
            <Body message={message} />
          </div>
        ) : null}
      </div>
    </Reveal>
  )
}
