import { useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Reveal from '../../components/Reveal.jsx'
import { T } from '../../i18n/fa.js'
import { checkable } from '../../lib/keys.js'

const PHONE = '(max-width: 640px)'

function usePhone() {
  const [phone, setPhone] = useState(() => !!(window.matchMedia && window.matchMedia(PHONE).matches))

  useEffect(() => {
    if (!window.matchMedia) return undefined
    const query = window.matchMedia(PHONE)
    const update = () => setPhone(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  return phone
}

function TypeRow({ label, selected, onToggle }) {
  return (
    <div className={'msrow' + (selected ? ' sel' : '')} {...checkable('checkbox', selected, onToggle)}>
      <span className="mscheck" />
      <span>{label}</span>
    </div>
  )
}

function GroupHead({ label, count, selected, partial, phone, open, onToggle, onOpen }) {
  const cls = 'msrow lgfgh' + (selected ? ' sel' : '') + (partial ? ' part' : '')
  const state = partial ? 'mixed' : selected ? 'true' : 'false'
  if (!phone) {
    return (
      <div className={cls} {...checkable('checkbox', selected, onToggle)} aria-checked={state}>
        <span className="mscheck" />
        <b>{label}</b>
        <span className="mssub">{count}</span>
      </div>
    )
  }
  return (
    <div className={cls + ' lgfsplit'}>
      <span className="lgfck" {...checkable('checkbox', selected, onToggle)} aria-checked={state} aria-label={label}>
        <span className="mscheck" />
      </span>
      <button type="button" className="lgfexp" aria-expanded={open} onClick={onOpen}>
        <b>{label}</b>
        <span className="mssub">{count}</span>
        <Icon name="chev" />
      </button>
    </div>
  )
}

export default function LogFiltersPanel({ evTypes, evGroups, hidden, onToggleType, onToggleGroup }) {
  const phone = usePhone()
  const [open, setOpen] = useState({})

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
            <div className="mslist" key={group}>
              <GroupHead
                label={groupLabel}
                count={shown + '/' + rows.length}
                selected={shown > 0}
                partial={shown > 0 && shown < rows.length}
                phone={phone}
                open={!!open[group]}
                onToggle={() => onToggleGroup(group)}
                onOpen={() => setOpen((prev) => ({ ...prev, [group]: !prev[group] }))}
              />
              <Reveal show={!phone || !!open[group]}>
                {rows.map(([key, , label]) => (
                  <TypeRow key={key} label={label} selected={!hidden[key]} onToggle={() => onToggleType(key)} />
                ))}
              </Reveal>
            </div>
          )
        })}
      </div>
    </div>
  )
}
