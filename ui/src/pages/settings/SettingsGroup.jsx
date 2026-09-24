import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'

export default function SettingsGroup({ section, icon, titleKey, chipKey, tone, children }) {
  const Tag = section ? 'section' : 'div'
  return (
    <Tag className={(section ? 'sgsec ' : 'card sg ') + tone}>
      <div className="sghd">
        <span className="sgt">
          <Icon name={icon} />
        </span>
        <b>{T(titleKey)}</b>
        <span className="schip">{T(chipKey)}</span>
      </div>
      <div className="sgb">{children}</div>
    </Tag>
  )
}
