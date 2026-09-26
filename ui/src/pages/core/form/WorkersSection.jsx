import { ScrollSeg, SegOpt } from './controls.jsx'
import { wkCarrier, wkShared } from './gates.js'
import { workerCounts } from './presets.js'
import { T } from '../../../i18n/fa.js'

function workersLabel(name, cpus) {
  const base = T('workers_lbl_node').split('{n}').join(name || '')
  return cpus ? base + ' · ' + T('workers_lbl_cores').split('{c}').join(String(cpus)) : base
}

function Picker({ counts, label, value, order, onPick }) {
  return (
    <div style={{ order }}>
      {label ? (
        <div className="muted" style={{ fontSize: 11, marginTop: 7 }}>
          {label}
        </div>
      ) : null}
      <ScrollSeg>
        {counts.map((n) => (
          <SegOpt
            key={n}
            on={n === value}
            title={String(n)}
            sub={T('workers_' + n)}
            onClick={() => onPick(n)}
          />
        ))}
      </ScrollSeg>
    </div>
  )
}

export default function WorkersSection({ form, cfg, sides, patch }) {
  if (!wkCarrier(form)) return null
  const counts = workerCounts(cfg.workers_max)

  if (wkShared(form)) {
    return (
      <div style={{ marginTop: 11 }}>
        <label className="first">{T('workers_lbl')}</label>
        <Picker counts={counts} value={form.WorkersA} onPick={(n) => patch({ WorkersA: n, WorkersB: n })} />
      </div>
    )
  }

  const serverIsA = form.Srv !== 'b'
  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">{T('workers_lbl')}</label>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <Picker
          counts={counts}
          label={workersLabel(sides.a.name, sides.a.cpus)}
          value={form.WorkersA}
          order={serverIsA ? 0 : 1}
          onPick={(n) => patch({ WorkersA: n })}
        />
        <Picker
          counts={counts}
          label={workersLabel(sides.b.name, sides.b.cpus)}
          value={form.WorkersB}
          order={serverIsA ? 1 : 0}
          onPick={(n) => patch({ WorkersB: n })}
        />
      </div>
    </div>
  )
}
