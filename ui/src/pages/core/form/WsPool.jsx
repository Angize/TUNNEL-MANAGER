import { useEffect, useState } from 'react'
import Field from '../../../components/Field.jsx'
import Icon from '../../../components/Icon.jsx'
import Select from '../../../components/Select.jsx'
import {
  Accordion,
  ActionButton,
  Badges,
  Countdown,
  EDGE_TITLES,
  ProgressBar,
  StaleCap,
  healthTone,
  isBurned,
} from './HealthRow.jsx'
import useSecondTick from './useSecondTick.js'
import { poolRotateItems } from './presets.js'
import { poolValid } from './validate.js'
import { alertBox } from '../../../lib/dialog.js'
import { toast } from '../../../lib/toast.js'
import { T, TF } from '../../../i18n/fa.js'
import { edgePort, hasCdnKey, providerName, splitZoneKey, tlsEdges, zoneKey } from '../../../lib/cdn.js'
import { WarnCap } from './controls.jsx'
import Reveal from '../../../components/Reveal.jsx'
import CdnMaker from './CdnMaker.jsx'
import ZoneNotes from './ZoneNotes.jsx'
import CleanEdges, { edgeRow } from './CleanEdges.jsx'
import { LTR_TEXT } from '../../../lib/form.js'

const KINDS = [
  { kind: 'ip', label: () => T('pool_ip_lbl'), placeholder: '104.16.0.1:443' },
  { kind: 'sni', label: () => T('pool_sni_lbl'), placeholder: 'cdn.example.com' },
]

function EdgeRow({ value, kind, owner, health, active, lid, pending, status, fresh, onRetest, onSelect, onDelete }) {
  const tone = healthTone(health, active, EDGE_TITLES)
  const burned = isBurned(health)
  const isTarget = pending && pending.kind === kind && pending.key === value

  return (
    <div className={'erow ' + tone.row + (health && health.state === 'dead' ? ' dead' : '') + (fresh ? ' fresh' : '')}>
      <span className={'estat ' + tone.stat} title={tone.title}>
        <Icon name={tone.icon} />
      </span>
      <span className="eip" title={value}>
        {value}
      </span>
      {owner ? <span className="cdnownchip">{TF('cdn_placed_by', { p: providerName(owner) })}</span> : null}
      {burned ? (
        <span className="ert">
          <Countdown health={health} now={status.now} polledMs={status.polledMs} />
          <ProgressBar health={health} now={status.now} polledMs={status.polledMs} />
        </span>
      ) : null}
      <span className="eacts">
        {burned && lid ? (
          <ActionButton
            icon="redo"
            title={T('pa_testnow')}
            onClick={() => onRetest(kind, value)}
          />
        ) : null}
        {lid && health ? (
          <ActionButton
            icon="pin"
            tone={'aim' + (active ? ' on' : '')}
            title={active ? T('pa_active_ip') : T('pa_activate')}
            disabled={!!pending}
            spinning={!!isTarget}
            onClick={() => onSelect(kind, value)}
          />
        ) : null}
        <ActionButton
          icon="trash"
          tone="del"
          title={T('tip_delete')}
          onClick={() => onDelete(kind, value)}
        />
      </span>
    </div>
  )
}

export default function WsPool({ form, enums, lid, live, edges, keys, owners, serverIp, onCdnMade, patch }) {
  const [open, setOpen] = useState({})
  const [draft, setDraft] = useState({})
  const [fresh, setFresh] = useState('')
  const [making, setMaking] = useState(false)
  const pool = form.pool
  const status = live.status
  useSecondTick(true)
  const items = poolRotateItems()
  const owned = pool.sni.map((h) => (owners || {})[h]).filter(Boolean)
  const ownedBy = (p) => owned.some((r) => r.provider === p)
  const cfOwned = ownedBy('cf')
  const anyOwned = owned.length > 0
  const zones = [...new Set(owned.map((r) => zoneKey(r.provider, r.zone)))].sort().map(splitZoneKey)
  const provs = [...new Set(owned.map((r) => r.provider))]
  const mixed = provs.length > 1
  const groupOf = (ip) => (mixed ? pool.ipCdn[ip] || owned[0].provider : '')
  const groups = JSON.stringify(mixed ? Object.fromEntries(pool.ip.map((ip) => [ip, groupOf(ip)])) : {})
  const manual = mixed ? pool.sni.find((h) => !(owners || {})[h]) : ''
  const bare = mixed ? provs.filter((p) => !pool.ip.some((ip) => groupOf(ip) === p)) : []
  const sections = (mixed ? provs : ['']).map((group) => ({ kind: 'ip', group })).concat([{ kind: 'sni', group: '' }])

  useEffect(() => {
    if (!!form.poolCdn !== anyOwned) patch({ poolCdn: anyOwned })
  }, [anyOwned, form.poolCdn, patch])
  useEffect(() => {
    if (groups !== JSON.stringify(pool.ipCdn)) patch({ pool: { ...pool, ipCdn: JSON.parse(groups) } })
  }, [groups, pool, patch])
  const needs443 = (group) => (group ? group === 'cf' : cfOwned)
  const cleanFor = (group) =>
    tlsEdges(edges).filter((v) => !pool.ip.includes(v) && (!needs443(group) || edgePort(v) === 443))
  const off443 = pool.ip.some((v) => needs443(groupOf(v)) && edgePort(v) !== 443)

  const setPool = (next) => patch({ pool: { ...pool, ...next } })

  const add = (kind, group, picked) => {
    const sec = kind + group
    let value = (picked || draft[sec] || '').trim()
    if (kind === 'sni') value = value.toLowerCase()
    if (!value) return
    if (!poolValid(kind, value, enums)) {
      alertBox(kind === 'ip' ? T('pool_bad_ip') : T('pool_bad_dom'))
      return
    }
    if (!picked) setDraft({ ...draft, [sec]: '' })
    if (pool[kind].includes(value) && (!group || groupOf(value) === group)) return
    setPool({
      [kind]: pool[kind].includes(value) ? pool[kind] : pool[kind].concat([value]),
      ...(group ? { ipCdn: { ...pool.ipCdn, [value]: group } } : {}),
    })
    setFresh(kind + ':' + value)
    setOpen({ ...open, [sec]: true })
  }

  const addHosts = (rows) => {
    const hosts = rows.map((r) => r.host).filter((h) => !pool.sni.includes(h))
    setMaking(false)
    if (!hosts.length) return
    setPool({ sni: pool.sni.concat(hosts) })
    setFresh('sni:' + hosts[hosts.length - 1])
    setOpen({ ...open, sni: true })
  }

  const remove = (kind, value) => {
    let ip = pool.ip.length
    let sni = pool.sni.length
    if (kind === 'ip') ip--
    else sni--
    if (ip < 1 || sni < 1) {
      toast(T('pool_need_clean'), 'err')
      return
    }
    if (ip < 2 && sni < 2) {
      toast(T('pool_need_axis'), 'err')
      return
    }
    setPool({ [kind]: pool[kind].filter((x) => x !== value) })
  }

  return (
    <div style={{ marginTop: 11 }}>
      <StaleCap status={status} />
      {sections.map(({ kind, group }) => {
        const sec = kind + group
        const { label, placeholder } = KINDS.find((k) => k.kind === kind)
        const title = group ? TF('pool_ip_lbl_cdn', { p: providerName(group) }) : label()
        const entries = group ? pool.ip.filter((ip) => groupOf(ip) === group) : pool[kind]
        let suspect = 0
        let dead = 0
        for (const value of entries) {
          const health = status.live[kind + ':' + value]
          if (health && health.state === 'suspect') suspect++
          else if (health && health.state === 'dead') dead++
        }
        return (
          <Accordion
            key={sec}
            label={title}
            collapsible
            open={!!open[sec]}
            onToggle={() => setOpen({ ...open, [sec]: !open[sec] })}
            badges={<Badges total={entries.length} suspect={suspect} dead={dead} />}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {entries.length ? (
                entries.map((value) => (
                  <EdgeRow
                    key={value}
                    value={value}
                    kind={kind}
                    owner={kind === 'sni' ? ((owners || {})[value] || {}).provider : ''}
                    health={status.live[kind + ':' + value]}
                    active={status.act[kind] === value}
                    lid={lid}
                    pending={live.pending}
                    status={status}
                    fresh={fresh === kind + ':' + value}
                    onRetest={live.retest}
                    onSelect={live.select}
                    onDelete={remove}
                  />
                ))
              ) : (
                <div className="pempty">{T('pool_empty')}</div>
              )}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
              <input
                className="mono"
                {...LTR_TEXT}
                aria-label={title}
                style={{ flex: '1 1 160px', minWidth: 0, textAlign: 'left' }}
                placeholder={group === 'ar' ? '185.143.233.1:443' : placeholder}
                value={draft[sec] || ''}
                onChange={(e) => setDraft({ ...draft, [sec]: e.target.value })}
              />
              <button type="button" className="padd" onClick={() => add(kind, group)}>
                +
              </button>
              {kind === 'sni' && hasCdnKey(keys) ? (
                <button
                  type="button"
                  className={'ghost tone tone-renew cdnmake' + (making ? ' on' : '')}
                  aria-expanded={making}
                  onClick={() => setMaking(!making)}
                >
                  <Icon name="globe" />
                  {T('cdn_make_open')}
                </button>
              ) : null}
              {kind === 'ip' ? (
                <CleanEdges
                  items={cleanFor(group).map(edgeRow)}
                  value=""
                  note={T(edges && edges.length ? 'edge_pool_all' : 'edge_list_empty')}
                  onPick={(v) => add('ip', group, v)}
                />
              ) : null}
            </div>
            {kind === 'sni' ? (
              <Reveal show={making}>
                <CdnMaker
                  form={form}
                  keys={keys}
                  serverIp={serverIp}
                  inUse={pool.sni}
                  multi
                  onMade={onCdnMade}
                  onClose={() => setMaking(false)}
                  onPlace={addHosts}
                />
              </Reveal>
            ) : null}
          </Accordion>
        )
      })}
      {bare.map((p) => (
        <WarnCap key={p} text={TF('pool_group_no_ip', { p: providerName(p) })} />
      ))}
      {manual ? <WarnCap text={TF('pool_mixed_manual', { h: manual })} /> : null}
      {cfOwned && off443 ? <WarnCap tone="gold" text={T('cdn_pool_443')} /> : null}
      {form.Ech && ownedBy('ar') ? <WarnCap text={T('cdn_pool_ech_ar')} /> : null}
      <ZoneNotes form={form} zones={zones} />
      <Field label={T('rot_int_lbl')}>
        <Select
          items={items}
          value={pool.rotate}
          placeholder={T('rot_int_lbl')}
          onChange={(v) => setPool({ rotate: +v })}
        />
      </Field>
    </div>
  )
}
