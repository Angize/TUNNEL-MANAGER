import { ScrollSeg, SegOpt } from './controls.jsx'
import { wkCarrier } from './gates.js'
import { workerCounts } from './presets.js'
import { T } from '../../../i18n/fa.js'

function workersLabel(name, cpus) {
  const base = T('workers_lbl_node').split('{n}').join(name || '')
  return cpus ? base + ' · ' + T('workers_lbl_cores').split('{c}').join(String(cpus)) : base
}

function SideWorkers({ counts, name, cpus, value, order, onPick }) {
  return (
    <div style={{ order }}>
      <div className="muted" style={{ fontSize: 11, marginTop: 7 }}>
        {workersLabel(name, cpus)}
      </div>
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
  const serverIsA = form.Srv !== 'b'

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">{T('workers_lbl')}</label>
      {form.Tr === 'tcp' || form.Tr === 'ws' ? (
        <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
          {T('workers_conn_d')}
        </div>
      ) : null}
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <SideWorkers
          counts={counts}
          name={sides.a.name}
          cpus={sides.a.cpus}
          value={form.WorkersA}
          order={serverIsA ? 0 : 1}
          onPick={(n) => patch({ WorkersA: n })}
        />
        <SideWorkers
          counts={counts}
          name={sides.b.name}
          cpus={sides.b.cpus}
          value={form.WorkersB}
          order={serverIsA ? 1 : 0}
          onPick={(n) => patch({ WorkersB: n })}
        />
      </div>
    </div>
  )
}
