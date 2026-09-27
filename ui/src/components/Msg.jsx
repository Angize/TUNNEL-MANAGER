import { useRef } from 'react'
import Reveal from './Reveal.jsx'
import { Check } from './Marks.jsx'
import useHeightTween from '../lib/useHeightTween.js'

export default function Msg({ text, cls, check, style }) {
  const box = useRef(null)
  useHeightTween(box, text, !!text)
  return (
    <Reveal show={!!text}>
      <div ref={box} className={'msg' + (cls ? ' ' + cls : '')} style={style}>
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
