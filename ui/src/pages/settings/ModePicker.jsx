import Modal from '../../components/Modal.jsx'
import { T } from '../../i18n/fa.js'

export function modeLabel(mode) {
  return mode === 'auto' ? T('set_mode_auto') : T('set_mode_alert')
}

const OPTIONS = [
  { mode: 'auto', isDefault: false },
  { mode: 'alert', isDefault: true },
]

export default function ModePicker({ value, onPick, onClose }) {
  return (
    <Modal bare cls="modesheet" onClose={onClose}>
      <div className="modelist">
        {OPTIONS.map(({ mode, isDefault }) => (
          <div
            key={mode}
            className={'mopt' + (value === mode ? ' on' : '')}
            onClick={() => onPick(mode)}
          >
            <span className="mrad" />
            <span className="mt">{modeLabel(mode)}</span>
            {isDefault ? <span className="mdf">{T('set_default')}</span> : null}
          </div>
        ))}
      </div>
    </Modal>
  )
}
