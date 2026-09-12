import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'

export default function SettingsGroup({ icon, titleKey, chipKey, tone, children }) {
  return (
    <div className={'card sg ' + tone}>
      <div className="sghd">
        <span className="sgt">
          <Icon name={icon} />
        </span>
        <b>{T(titleKey)}</b>
        <span className="schip">{T(chipKey)}</span>
      </div>
      <div className="sgb">{children}</div>
    </div>
  )
}
