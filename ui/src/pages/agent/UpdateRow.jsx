import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'

export default function UpdateRow({ icon, title, sub, state, goIcon, goLabel, goDisabled, onGo, open, onToggle, children }) {
  return (
    <>
      <div className="ophd uprow">
        <span className="sgt">
          <Icon name={icon} />
          {state ? <i className={'st ' + state.cls} role="img" aria-label={state.text} title={state.text} /> : null}
        </span>
        <div className="hd2">
          <b>{title}</b>
          <small>{sub}</small>
        </div>
        <button type="button" className="primary glass upgo" disabled={goDisabled} onClick={onGo}>
          <Icon name={goIcon} />
          {goLabel}
        </button>
        <button
          type="button"
          className="ghost tone tone-more upx"
          aria-expanded={open}
          aria-label={T('ag_more')}
          title={T('ag_more')}
          onClick={onToggle}
        >
          <Icon name="chev" />
        </button>
      </div>
      {open ? <div className="upmore">{children}</div> : null}
    </>
  )
}
