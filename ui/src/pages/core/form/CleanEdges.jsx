import { useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import { SelectPop } from '../../../components/Select.jsx'
import { checkable } from '../../../lib/keys.js'
import { edgePort } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

export function edgeRow(v) {
  const port = edgePort(v)
  return { v, label: v, sub: port ? TF('edges_port', { p: port }) : T('edges_port_any') }
}

export default function CleanEdges({ items, value, note, onPick }) {
  const [open, setOpen] = useState(false)
  const btn = useRef(null)
  const n = items.filter((it) => it.v !== 'host').length

  const close = () => {
    setOpen(false)
    if (btn.current) btn.current.focus()
  }

  return (
    <>
      <button
        ref={btn}
        type="button"
        className={'ghost tone tone-renew cdnmake' + (open ? ' on' : '')}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen(true)}
      >
        <Icon name="list" />
        {n ? TF('edge_menu_n', { n }) : T('edge_menu')}
      </button>
      {open ? (
        <SelectPop anchor={btn} label={T('edge_menu')} onClose={close}>
          <div className="sspop">
            {items.length ? (
              <div className="sspoplist" role="radiogroup">
                {items.map((it) => (
                  <div
                    key={it.v}
                    className={'msrow' + (it.v === value ? ' sel' : '')}
                    {...checkable('radio', it.v === value, () => {
                      close()
                      onPick(it.v)
                    })}
                  >
                    <span className="mscheck" />
                    <span className="mstx">
                      {it.v === 'host' ? (
                        <span className="msl">{it.label}</span>
                      ) : (
                        <span className="msl mono" dir="ltr">
                          {it.label}
                        </span>
                      )}
                      <span className="mssub cdnsub">{it.sub}</span>
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
            {n ? null : <div className="cdnedgenone">{note}</div>}
          </div>
        </SelectPop>
      ) : null}
    </>
  )
}
