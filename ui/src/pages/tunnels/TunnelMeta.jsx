import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import { T } from '../../i18n/fa.js'

const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

function SubnetRow({ link }) {
  return (
    <div>
      {T('subnet')}: <CopyValue text={link.subnet} />
    </div>
  )
}

function IdRow({ link }) {
  return (
    <div>
      {T('tid')}: <b>{link.tunnel_id}</b>
    </div>
  )
}

function IfaceRow({ link }) {
  return (
    <div>
      {T('iface')}: <b className="mono">{link.name}</b>
    </div>
  )
}

function ExtraRow({ link }) {
  if (link.type === 'ipsec') {
    return (
      <div className="wrap">
        {T('enc')}:{' '}
        <span className="enc">
          <Icon name="lock" />
          {T('encrypted')}
        </span>
      </div>
    )
  }
  if (PORT_TYPES.includes(link.type) && link.port) {
    return (
      <div>
        {T('udp_port')}: <b className="mono iso">{link.port}</b>
      </div>
    )
  }
  return null
}

export default function TunnelMeta({ link }) {
  return (
    <div className="enmeta">
      <div className="emcol">
        <SubnetRow link={link} />
        <IfaceRow link={link} />
      </div>
      <span className="tnarrow earrow">
        <Icon name="arrows" />
      </span>
      <div className="emcol">
        <IdRow link={link} />
        <ExtraRow link={link} />
      </div>
    </div>
  )
}
