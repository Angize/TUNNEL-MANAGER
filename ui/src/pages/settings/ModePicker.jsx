import { useEffect, useRef } from 'react'
import Modal from '../../components/Modal.jsx'
import { checkable } from '../../lib/keys.js'
import { T } from '../../i18n/fa.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

export function modeLabel(mode) {
  return mode === 'auto' ? T('set_mode_auto') : T('set_mode_alert')
}

const MODES = ['auto', 'alert']

export default function ModePicker({ value, onPick, onClose }) {
  const defaultMode = useUiConfig().settings_defaults.reconcile_mode
  const listRef = useRef(null)

  useEffect(() => {
    const list = listRef.current
    const row = list && (list.querySelector('.mopt.on') || list.querySelector('.mopt'))
    if (row) row.focus()
  }, [])

  return (
    <Modal bare cls="modesheet" label={T('set_on_ipchange')} onClose={onClose}>
      <div className="modelist" ref={listRef}>
        {MODES.map((mode) => (
          <div
            key={mode}
            className={'mopt' + (value === mode ? ' on' : '')}
            {...checkable('radio', value === mode, (e) => onPick(mode, e))}
          >
            <span className="mrad" />
            <span className="mt">{modeLabel(mode)}</span>
            {mode === defaultMode ? <span className="mdf">{T('set_default')}</span> : null}
          </div>
        ))}
      </div>
    </Modal>
  )
}
