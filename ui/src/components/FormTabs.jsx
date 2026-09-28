import { useId, useState } from 'react'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'
import './formtabs.css'

const TABS = [
  { v: 'ip', icon: 'pin', label: 'form_tab_ips' },
  { v: 'set', icon: 'cog', label: 'form_tab_set' },
]

export default function FormTabs({ tab, onTab, panes }) {
  const base = useId()
  const [tap, setTap] = useState(false)

  const onKey = (e) => {
    const at = TABS.findIndex((entry) => entry.v === tab)
    const next = {
      ArrowLeft: (at + 1) % TABS.length,
      ArrowRight: (at + TABS.length - 1) % TABS.length,
      Home: 0,
      End: TABS.length - 1,
    }[e.key]
    if (next === undefined) return
    e.preventDefault()
    setTap(false)
    onTab(TABS[next].v)
    document.getElementById(base + 't' + TABS[next].v).focus()
  }

  return (
    <>
      <div className="ctabs" role="tablist" onKeyDown={onKey}>
        {TABS.map((entry) => (
          <button
            key={entry.v}
            id={base + 't' + entry.v}
            type="button"
            role="tab"
            aria-selected={tab === entry.v ? 'true' : 'false'}
            aria-controls={base + 'p' + entry.v}
            tabIndex={tab === entry.v ? 0 : -1}
            className={'ctab' + (tab === entry.v ? ' on' : '')}
            onClick={(e) => {
              setTap(!!e.detail)
              onTab(entry.v)
            }}
          >
            <Icon name={entry.icon} />
            {T(entry.label)}
          </button>
        ))}
      </div>

      {TABS.map((entry) => (
        <div
          key={entry.v}
          id={base + 'p' + entry.v}
          role="tabpanel"
          aria-labelledby={base + 't' + entry.v}
          className={'ctabp' + (tab === entry.v ? ' on' : '') + (tap ? ' tap' : '')}
        >
          {panes[entry.v]}
        </div>
      ))}
    </>
  )
}
