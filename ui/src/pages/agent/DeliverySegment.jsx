import { T } from '../../i18n/fa.js'

const OPTIONS = [
  ['push', 'dlv_push_t'],
  ['github', 'dlv_git_t'],
  ['panel', 'dlv_pan_t'],
]

export default function DeliverySegment({ value, onChange }) {
  return (
    <div className="opdlv">
      <label>{T('dlv_lbl')}</label>
      <div className="seg2">
        {OPTIONS.map(([key, labelKey]) => (
          <button
            key={key}
            type="button"
            className={'segopt' + (key === value ? ' on' : '')}
            onClick={() => onChange(key)}
          >
            <b>{T(labelKey)}</b>
          </button>
        ))}
      </div>
    </div>
  )
}
