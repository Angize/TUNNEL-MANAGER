import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import { T } from '../../i18n/fa.js'

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

function TypeRow({ link }) {
  return (
    <div className="tagrow">
      {T('ttype')}: <span className={'tag ' + link.type}>{link.type}</span>
    </div>
  )
}

export default function TunnelMeta({ link }) {
  const portTypes = ['l2tpv3', 'fou', 'vxlan']
  let right
  let left

  if (link.type === 'ipsec') {
    right = (
      <>
        <SubnetRow link={link} />
        <IdRow link={link} />
        <IfaceRow link={link} />
      </>
    )
    left = (
      <>
        <TypeRow link={link} />
        <div className="wrap">
          {T('enc')}:{' '}
          <span className="enc">
            <Icon name="lock" color="var(--bad)" />
            {T('encrypted')}
          </span>
        </div>
      </>
    )
  } else if (portTypes.includes(link.type) && link.port) {
    right = (
      <>
        <SubnetRow link={link} />
        <IdRow link={link} />
        <IfaceRow link={link} />
      </>
    )
    left = (
      <>
        <TypeRow link={link} />
        <div>
          {T('udp_port')}: <b className="mono">{link.port}</b>
        </div>
      </>
    )
  } else {
    right = (
      <>
        <SubnetRow link={link} />
        <IfaceRow link={link} />
      </>
    )
    left = (
      <>
        <IdRow link={link} />
        <TypeRow link={link} />
      </>
    )
  }

  return (
    <div className="enmeta">
      <div className="emcol">{right}</div>
      <span className="tnarrow earrow">↔</span>
      <div className="emcol">{left}</div>
    </div>
  )
}
