import { useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import {
  Accordion,
  ActionButton,
  Badges,
  Countdown,
  PEER_TITLES,
  ProgressBar,
  healthTone,
  isBurned,
} from './HealthRow.jsx'
import useSecondTick from './useSecondTick.js'
import { PEER_ACC_MIN } from './presets.js'
import { T } from '../../../i18n/fa.js'

function PeerRow({ side, ip, section, status, pending, tuning, live }) {
  const health = section.live[ip]
  const active = section.active === ip
  const tone = healthTone(health, active, PEER_TITLES)
  const burned = isBurned(health)
  const isTarget = pending && pending.side === side && pending.key === ip

  return (
    <div className={'erow pcol ' + tone.row + (health && health.state === 'dead' ? ' dead' : '')}>
      <div className="etop">
        <span className={'estat ' + tone.stat} title={tone.title}>
          <Icon name={tone.icon} />
        </span>
        <span className="eip" title={ip}>
          {ip}
        </span>
        <span className="eacts">
          {burned ? (
            <ActionButton
              icon="redo"
              title={T('pa_testnow')}
              onClick={() => live.retest(side, ip)}
            />
          ) : null}
          <ActionButton
            icon="pin"
            tone={'aim' + (active ? ' on' : '')}
            title={active ? T('pa_active_ip') : T('pa_activate')}
            disabled={!!pending}
            spinning={!!isTarget}
            onClick={() => live.select(side, ip)}
          />
        </span>
      </div>
      {burned ? (
        <div className="ecd">
          <Countdown health={health} now={status.now} polledMs={status.polledMs} />
          <ProgressBar
            health={health}
            now={status.now}
            polledMs={status.polledMs}
            tuning={tuning}
          />
        </div>
      ) : null}
    </div>
  )
}

function PeerBox({ side, label, status, pending, tuning, live, open, onToggle }) {
  const section = status[side]
  if (!section || section.addrs.length < 2) return null

  let suspect = 0
  let dead = 0
  for (const ip of section.addrs) {
    const health = section.live[ip]
    if (health && health.state === 'suspect') suspect++
    else if (health && health.state === 'dead') dead++
  }

  const collapsible = section.addrs.length > PEER_ACC_MIN

  return (
    <Accordion
      label={label}
      collapsible={collapsible}
      open={collapsible ? open : true}
      onToggle={onToggle}
      badges={<Badges total={section.addrs.length} suspect={suspect} dead={dead} />}
    >
      <div className="rpool">
        {section.addrs.map((ip) => (
          <PeerRow
            key={ip}
            side={side}
            ip={ip}
            section={section}
            status={status}
            pending={pending}
            tuning={tuning}
            live={live}
          />
        ))}
      </div>
    </Accordion>
  )
}

export default function PeerLive({ live, tuning }) {
  const [open, setOpen] = useState({ dst: true, src: true })
  const { status, pending } = live
  useSecondTick(true)
  const shown = ['dst', 'src'].filter((side) => status[side] && status[side].addrs.length >= 2)

  return (
    <div className="peerlive">
      <div className="pllabel">{T('peer_live_hd')}</div>
      {shown.length ? (
        shown.map((side) => (
          <PeerBox
            key={side}
            side={side}
            label={side === 'dst' ? T('dst_ip') : T('src_ip')}
            status={status}
            pending={pending}
            tuning={tuning}
            live={live}
            open={open[side]}
            onToggle={() => setOpen({ ...open, [side]: !open[side] })}
          />
        ))
      ) : (
        <div className="muted" style={{ fontSize: 11, lineHeight: 1.7 }}>
          {T('peer_live_empty')}
        </div>
      )}
    </div>
  )
}
