import { useId } from 'react'
import Stepper from '../../../components/Stepper.jsx'
import { wkShared } from './gates.js'
import { T, TF } from '../../../i18n/fa.js'

function Picker({ max, name, side, value, order, onPick }) {
  const id = useId()
  return (
    <div className="wkcol" style={{ order }}>
      {side ? (
        <div className="wksub" id={id + 's'}>
          <b>{TF('workers_lbl_node', { n: side.name || '' })}</b>
          {side.cpus ? <span>{' · ' + TF('workers_lbl_cores', { c: side.cpus })}</span> : null}
        </div>
      ) : null}
      <Stepper
        min={1}
        max={max}
        readOnly
        value={String(value)}
        aria-label={name}
        aria-describedby={(side ? id + 's ' : '') + id + 'h'}
        onChange={(v) => onPick(Number(v))}
      />
      <div className="fldhint" id={id + 'h'}>
        {T('workers_' + value)}
      </div>
    </div>
  )
}

export default function WorkersSection({ form, cfg, sides, patch }) {
  const name = T('workers_lbl')
  const shared = wkShared(form)
  const serverIsA = form.Srv !== 'b'

  return (
    <div className="wksec">
      <label className="first">{name}</label>
      <div className={'wkgrid' + (shared ? '' : ' two')}>
        {shared ? (
          <Picker
            max={cfg.workers_max}
            name={name}
            value={form.WorkersA}
            onPick={(n) => patch({ WorkersA: n, WorkersB: n })}
          />
        ) : (
          <>
            <Picker
              max={cfg.workers_max}
              name={name}
              side={sides.a}
              value={form.WorkersA}
              order={serverIsA ? 0 : 1}
              onPick={(n) => patch({ WorkersA: n })}
            />
            <Picker
              max={cfg.workers_max}
              name={name}
              side={sides.b}
              value={form.WorkersB}
              order={serverIsA ? 1 : 0}
              onPick={(n) => patch({ WorkersB: n })}
            />
          </>
        )}
      </div>
    </div>
  )
}
