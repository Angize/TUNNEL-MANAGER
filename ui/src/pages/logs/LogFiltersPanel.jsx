import { T } from '../../i18n/fa.js'

function Row({ label, selected, partial, sub, bold, onToggle }) {
  const activate = (e) => {
    if (e.key !== undefined && e.key !== ' ' && e.key !== 'Enter') return
    if (e.key !== undefined) e.preventDefault()
    onToggle()
  }
  return (
    <div
      className={
        'msrow' + (bold ? ' lgfgh' : '') + (selected ? ' sel' : '') + (partial ? ' part' : '')
      }
      role="button"
      tabIndex={0}
      aria-pressed={bold ? undefined : selected ? 'true' : 'false'}
      onClick={activate}
      onKeyDown={activate}
    >
      <span className="mscheck" />
      {bold ? <b>{label}</b> : <span>{label}</span>}
      {sub ? <span className="mssub">{sub}</span> : null}
    </div>
  )
}

export default function LogFiltersPanel({ evTypes, evGroups, hidden, onToggleType, onToggleGroup }) {
  return (
    <div className="card lgf">
      <div className="lgfhead">
        {T('logf_head')}
        <span className="mssub">{T('logf_hint')}</span>
      </div>
      <div className="lgfgrid">
        {evGroups.map(([group, groupLabel]) => {
          const rows = evTypes.filter(([, g]) => g === group)
          const shown = rows.filter(([key]) => !hidden[key]).length
          return (
            <div className="lgfg mslist" key={group}>
              <Row
                bold
                label={groupLabel}
                selected={shown > 0}
                partial={shown > 0 && shown < rows.length}
                sub={shown + '/' + rows.length}
                onToggle={() => onToggleGroup(group)}
              />
              {rows.map(([key, , label]) => (
                <Row
                  key={key}
                  label={label}
                  selected={!hidden[key]}
                  onToggle={() => onToggleType(key)}
                />
              ))}
            </div>
          )
        })}
      </div>
    </div>
  )
}
