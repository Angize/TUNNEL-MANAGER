import { T } from '../../i18n/fa.js'
import { checkable } from '../../lib/keys.js'

export const DEFAULT_ROTATE_MINUTES = 5

export function rotateBody(rotate, minutes) {
  return rotate ? { rotate, interval_min: minutes.trim() || DEFAULT_ROTATE_MINUTES } : { rotate }
}

export default function RotateFields({ rotate, minutes, onRotate, onMinutes }) {
  return (
    <>
      <label>{T('pf_rot_between')}</label>
      <div className="tgl">
        <span
          className={'tglsw' + (rotate ? ' on' : '')}
          {...checkable('switch', rotate, () => onRotate(!rotate))}
        />
        <span className="muted">{rotate ? T('on_word') : T('off_word')}</span>
      </div>

      {rotate ? (
        <div>
          <label>{T('pf_rot_interval')}</label>
          <input value={minutes} onChange={(e) => onMinutes(e.target.value)} />
        </div>
      ) : null}

      <div className="muted" style={{ fontSize: 11.5, marginTop: 9 }}>
        {T('pf_rot_note')}
      </div>
    </>
  )
}
