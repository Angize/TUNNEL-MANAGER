import Icon, { Glyph } from './Icon.jsx'
import { T } from '../i18n/fa.js'

function PeerChip({ peer }) {
  return (
    <span className="ippeer">
      <Glyph name="link" width={11} height={11} style={{ verticalAlign: '-1px' }} />
      <bdi>{peer.name || peer.type}</bdi>
      <span className="ipo">
        <Icon name="arrows" />
        <bdi>{peer.node}</bdi>
      </span>
    </span>
  )
}

export default function IpChips({ entry }) {
  return (
    <>
      {entry.peers.map((peer, i) => (
        <PeerChip key={peer.node + ':' + i} peer={peer} />
      ))}
      {entry.pf.map((name) => (
        <span className="ippf" key={'pf:' + name}>
          <Icon name="portForward" />
          {T('nd_portfw') + ' ·'}
          <bdi>{name}</bdi>
        </span>
      ))}
      {entry.free ? <span className="ipfree">{T('free')}</span> : null}
    </>
  )
}
