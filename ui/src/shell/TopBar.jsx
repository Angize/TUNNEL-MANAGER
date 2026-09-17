import Icon from '../components/Icon.jsx'
import { T } from '../i18n/fa.js'
import { logout } from '../lib/api.js'

export default function TopBar({ dark, onToggleTheme }) {
  return (
    <div className="mtop">
      <button className="hb" title={T('nav_logout')} onClick={logout}>
        <Icon name="logout" />
      </button>
      <div className="sbrand">
        <span className="logo" style={{ width: 28, height: 28, fontSize: 14 }}>
          <Icon name="shield" />
        </span>
        <span>TUNNEL-MANAGER</span>
      </div>
      <button className="hb" title={T(dark ? 'theme_to_light' : 'theme_to_dark')} onClick={onToggleTheme}>
        <Icon name={dark ? 'sun' : 'moon'} />
      </button>
    </div>
  )
}
