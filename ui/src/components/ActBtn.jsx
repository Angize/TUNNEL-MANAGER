import Icon from './Icon.jsx'

export default function ActBtn({ cls, title, icon, busy, locked, style, onClick }) {
  return (
    <button
      type="button"
      className={'act' + (cls ? ' ' + cls : '')}
      title={title}
      style={style}
      disabled={!!locked}
      aria-busy={!!busy}
      onClick={onClick}
    >
      {busy ? <span className="bspin ink" /> : <Icon name={icon} />}
    </button>
  )
}
