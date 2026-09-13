import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import { Kv, KvRow } from '../../components/Kv.jsx'
import { T } from '../../i18n/fa.js'

const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

export default function TunnelMeta({ link }) {
  return (
    <Kv>
      <KvRow label={T('ttype')}>
        <span className={'tag ' + link.type}>{link.type}</span>
      </KvRow>
      <KvRow label={T('subnet')} mono>
        <CopyValue text={link.subnet} />
      </KvRow>
      <KvRow label={T('tid')} mono>
        {link.tunnel_id}
      </KvRow>
      <KvRow label={T('iface')} mono>
        {link.name}
      </KvRow>
      {link.type === 'ipsec' ? (
        <KvRow label={T('enc')}>
          <span className="enc">
            <Icon name="lock" color="var(--bad)" />
            {T('encrypted')}
          </span>
        </KvRow>
      ) : null}
      {PORT_TYPES.includes(link.type) && link.port ? (
        <KvRow label={T('udp_port')} mono>
          {link.port}
        </KvRow>
      ) : null}
    </Kv>
  )
}
