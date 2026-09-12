import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'

export default function PageHead({ icon, titleKey, subKey }) {
  return (
    <>
      <h1>
        <Icon name={icon} color="var(--acc)" />
        {T(titleKey)}
      </h1>
      {subKey ? <p className="sub">{T(subKey)}</p> : null}
    </>
  )
}
