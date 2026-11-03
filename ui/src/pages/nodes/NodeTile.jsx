import Icon from '../../components/Icon.jsx'

export default function NodeTile({ icon, label, children, wide, line, ltr, warn, fresh }) {
  return (
    <div
      className={
        'nd-tile' + (wide ? ' nd-wide' : '') + (line ? ' nd-line' : '') + (warn ? ' kt-warn' : '') + (fresh ? ' kt-new' : '')
      }
    >
      <span className="medi">
        <Icon name={icon} />
      </span>
      <span>{label}</span>
      <b className={ltr ? 'ltr' : undefined}>{children}</b>
    </div>
  )
}
