import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Reveal from '../../components/Reveal.jsx'
import SwitchRow from '../../components/SwitchRow.jsx'
import { T } from '../../i18n/fa.js'

export const DEFAULT_ROTATE_MINUTES = 5

export function rotateBody(rotate, minutes) {
  return rotate ? { rotate, interval_min: minutes.trim() || DEFAULT_ROTATE_MINUTES } : { rotate }
}

export default function RotateFields({ rotate, minutes, onRotate, onMinutes }) {
  return (
    <>
      <SwitchRow
        on={rotate}
        title={T('pf_rot_between')}
        note={T('pf_rot_note')}
        onToggle={() => onRotate(!rotate)}
      />

      <Reveal show={rotate}>
        <Field label={T('pf_rot_interval')}>
          <NumberInput value={minutes} onChange={onMinutes} />
        </Field>
      </Reveal>
    </>
  )
}
