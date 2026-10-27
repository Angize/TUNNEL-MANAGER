import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'

function LinkMark() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ verticalAlign: '-1px' }}
    >
      <path d="M9 7H6a4 4 0 000 8h3M15 7h3a4 4 0 010 8h-3M8 11h8" />
    </svg>
  )
}

function PeerChip({ peer }) {
  return (
    <span className="ippeer">
      <LinkMark />
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
      {(entry.peers || []).map((peer, i) => (
        <PeerChip key={peer.node + ':' + i} peer={peer} />
      ))}
      {(entry.pf || []).map((name) => (
        <span className="ippf" key={'pf:' + name}>
          <Icon name="globe" /> {T('nd_portfw') + ' · ' + name}
        </span>
      ))}
      {entry.free ? <span className="ipfree">{T('free')}</span> : null}
    </>
  )
}
