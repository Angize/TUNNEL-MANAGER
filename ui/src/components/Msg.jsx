import Reveal from './Reveal.jsx'
import { Check } from './Marks.jsx'

export default function Msg({ text, cls, check, style }) {
  return (
    <Reveal show={!!text}>
      <div className={'msg' + (cls ? ' ' + cls : '')} style={style}>
        {text ? (
          <span key={text} className="msgt">
            {check ? <Check /> : null}
            {check ? ' ' + text : text}
          </span>
        ) : null}
      </div>
    </Reveal>
  )
}
