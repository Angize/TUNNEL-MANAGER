import Icon from '../components/Icon.jsx'

export default function TopBar({ dark, onMenu, onToggleTheme }) {
  return (
    <div className="mtop">
      <button className="hb" onClick={onMenu}>
        <Icon name="menu" />
      </button>
      <div className="sbrand">
        <span className="logo" style={{ width: 28, height: 28, fontSize: 14 }}>
          <Icon name="shield" />
        </span>
        <span>TUNNEL-MANAGER</span>
      </div>
      <button className="hb" onClick={onToggleTheme}>
        <Icon name={dark ? 'sun' : 'moon'} />
      </button>
    </div>
  )
}
