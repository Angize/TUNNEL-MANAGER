import { useState } from 'react'
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
import { T } from '../../../i18n/fa.js'

const KINDS = [
  { kind: 'ip', label: () => T('pool_ip_lbl'), placeholder: '104.16.0.1:443' },
  { kind: 'sni', label: () => T('pool_sni_lbl'), placeholder: 'cdn.example.com' },
]

function EdgeRow({ value, kind, health, active, lid, pending, tuning, status, onRetest, onSelect, onDelete }) {
  const tone = healthTone(health, active, EDGE_TITLES)
  const burned = isBurned(health)
  const isTarget = pending && pending.kind === kind && pending.key === value

  return (
    <div className={'erow ' + tone.row + (health && health.state === 'dead' ? ' dead' : '')}>
      <span className={'estat ' + tone.stat} title={tone.title}>
        <Icon name={tone.icon} />
      </span>
      <span className="eip" title={value}>
        {value}
      </span>
      {burned ? (
        <span className="ert">
          <Countdown health={health} now={status.now} polledMs={status.polledMs} />
          <ProgressBar
            health={health}
            now={status.now}
            polledMs={status.polledMs}
            tuning={tuning}
          />
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

export default function WsPool({ form, enums, tuning, lid, live, patch }) {
  const [open, setOpen] = useState({ ip: false, sni: false })
  const [draft, setDraft] = useState({ ip: '', sni: '' })
  const pool = form.pool
  const status = live.status
  useSecondTick(true)
  const items = poolRotateItems()

  const setPool = (next) => patch({ pool: { ...pool, ...next } })

  const add = (kind) => {
    let value = (draft[kind] || '').trim()
    if (kind === 'sni') value = value.toLowerCase()
    if (!value) return
    if (!poolValid(kind, value, enums)) {
      alertBox(kind === 'ip' ? T('pool_bad_ip') : T('pool_bad_dom'))
      return
    }
    setDraft({ ...draft, [kind]: '' })
    if (pool[kind].includes(value)) return
    setPool({ [kind]: pool[kind].concat([value]) })
    setOpen({ ...open, [kind]: true })
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
      {KINDS.map(({ kind, label, placeholder }) => {
        const entries = pool[kind]
        let suspect = 0
        let dead = 0
        for (const value of entries) {
          const health = status.live[kind + ':' + value]
          if (health && health.state === 'suspect') suspect++
          else if (health && health.state === 'dead') dead++
        }
        return (
          <Accordion
            key={kind}
            label={label()}
            collapsible
            open={open[kind]}
            onToggle={() => setOpen({ ...open, [kind]: !open[kind] })}
            badges={<Badges total={entries.length} suspect={suspect} dead={dead} />}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {entries.length ? (
                entries.map((value) => (
                  <EdgeRow
                    key={value}
                    value={value}
                    kind={kind}
                    health={status.live[kind + ':' + value]}
                    active={status.act[kind] === value}
                    lid={lid}
                    pending={live.pending}
                    tuning={tuning}
                    status={status}
                    onRetest={live.retest}
                    onSelect={live.select}
                    onDelete={remove}
                  />
                ))
              ) : (
                <div className="pempty">{T('pool_empty')}</div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
              <input
                className="mono"
                dir="ltr"
                style={{ flex: 1, textAlign: 'left' }}
                placeholder={placeholder}
                value={draft[kind]}
                onChange={(e) => setDraft({ ...draft, [kind]: e.target.value })}
              />
              <button
                type="button"
                onClick={() => add(kind)}
                style={{
                  background: 'var(--acc)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 9,
                  minWidth: 42,
                  fontSize: 18,
                  cursor: 'pointer',
                }}
              >
                +
              </button>
            </div>
          </Accordion>
        )
      })}
      <label style={{ marginTop: 14 }}>{T('rot_int_lbl')}</label>
      <Select
        items={items}
        value={pool.rotate}
        placeholder={T('rot_int_lbl')}
        onChange={(v) => setPool({ rotate: +v })}
      />
    </div>
  )
}
