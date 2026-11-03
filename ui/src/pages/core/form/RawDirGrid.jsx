import { useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import Reveal from '../../../components/Reveal.jsx'
import { ctbDefault } from './gates.js'
import { rawProfiles } from './presets.js'
import { Seg2, SegOpt } from './controls.jsx'
import { cleanPtype, ptypeErr } from './ptype.js'
import { T } from '../../../i18n/fa.js'

const PTYPE_SEGS = [
  ['', '0x0800', 'raw_ptype_def'],
  ['ffff', '0xffff', 'raw_ptype_common'],
  ['8847', '0x8847', 'raw_ptype_mpls'],
]

function PtypePick({ dir, value, onPick }) {
  const up = dir === 'up'
  const way = T(up ? 'raw_dir_up' : 'raw_dir_down')
  const [manual, setManual] = useState(false)
  const custom = manual || !PTYPE_SEGS.some(([hex]) => hex === value)
  const error = ptypeErr(value)
  const pick = (hex) => {
    setManual(false)
    onPick(hex)
  }
  return (
    <div className={'ptypepick ' + dir}>
      <div className="ptypedir">
        <Icon name={up ? 'upload' : 'download'} />
        {way}
      </div>
      <Seg2 label={T('raw_ptype_lbl') + ' · ' + way}>
        {PTYPE_SEGS.map(([hex, title, sub]) => (
          <SegOpt
            key={hex}
            on={!custom && value === hex}
            title={<bdi className="mono">{title}</bdi>}
            sub={T(sub)}
            onClick={() => pick(hex)}
          />
        ))}
        <SegOpt
          on={custom}
          title={custom && value ? <bdi className="mono">{'0x' + value}</bdi> : T('raw_ptype_custom')}
          sub={T(custom && value ? 'raw_ptype_custom' : 'raw_ptype_hex')}
          onClick={() => setManual(true)}
        />
      </Seg2>
      <Reveal show={custom}>
        <div className="ptypehex">
          <span>0x</span>
          <input
            className="mono"
            value={value}
            autoFocus={manual}
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            placeholder="0800"
            aria-label={T('raw_ptype_custom') + ' · ' + way}
            aria-invalid={error ? 'true' : undefined}
            onChange={(e) => onPick(cleanPtype(e.target.value))}
          />
        </div>
      </Reveal>
      {error ? (
        <div className="flderr" role="alert">
          <Icon name="warn" />
          <span>{error}</span>
        </div>
      ) : null}
    </div>
  )
}

function DirChip({ dir, on, profile, onPick }) {
  const up = dir === 'up'
  return (
    <button
      type="button"
      className={'dirchip ' + dir + (on ? ' on' : '')}
      aria-pressed={on ? 'true' : 'false'}
      aria-label={T(up ? 'raw_dir_up_aria' : 'raw_dir_down_aria').replace('{p}', profile)}
      onClick={onPick}
    >
      <Icon name={up ? 'upload' : 'download'} />
      {T(up ? 'raw_dir_up' : 'raw_dir_down')}
    </button>
  )
}

function DirPick({ dir, profile, from, to }) {
  const up = dir === 'up'
  return (
    <span className={'dirpick ' + dir}>
      <Icon name={up ? 'upload' : 'download'} />
      <span>
        {T(up ? 'raw_dir_up' : 'raw_dir_down')} <b>{profile.toUpperCase()}</b>
        {from && to ? (
          <>
            {' · ' + T('raw_dir_from') + ' '}
            <bdi>{from}</bdi>
            {' ' + T('raw_dir_to') + ' '}
            <bdi>{to}</bdi>
          </>
        ) : null}
      </span>
    </span>
  )
}

export default function RawDirGrid({ form, cfg, sides, patch }) {
  const client = sides[form.Srv === 'a' ? 'b' : 'a'].name
  const server = sides[form.Srv === 'a' ? 'a' : 'b'].name

  const pick = (key, current, value) => {
    if (value === current) return
    patch(ctbDefault(value, cfg.enums) ? { [key]: value, Ctb: true } : { [key]: value })
  }

  return (
    <div>
      <label>{T('raw_dir_lbl')}</label>
      <div className="pgrid dirgrid" role="group" aria-label={T('raw_dir_lbl')}>
        {rawProfiles().map((profile) => {
          const up = profile.v === form.RawProfile
          const down = profile.v === form.RawProfileDown
          return (
            <div key={profile.v} className={'ptile dirtile' + (up ? ' upon' : '') + (down ? ' dnon' : '')}>
              <div className="pn">{profile.v}</div>
              <div className="pmeta">{profile.m}</div>
              <div className="dirchips">
                <DirChip
                  dir="up"
                  on={up}
                  profile={profile.v}
                  onPick={() => pick('RawProfile', form.RawProfile, profile.v)}
                />
                <DirChip
                  dir="down"
                  on={down}
                  profile={profile.v}
                  onPick={() => pick('RawProfileDown', form.RawProfileDown, profile.v)}
                />
              </div>
            </div>
          )
        })}
      </div>
      <div className="dirsum">
        <DirPick dir="up" profile={form.RawProfile} from={client} to={server} />
        <DirPick dir="down" profile={form.RawProfileDown} from={server} to={client} />
      </div>
      <Reveal show={form.RawProfile === 'gre' || form.RawProfileDown === 'gre'}>
        <div className="greptype">
          <label>{T('raw_ptype_lbl')}</label>
          {form.RawProfile === 'gre' ? (
            <PtypePick key={'up' + form.Srv} dir="up" value={form.GrePtype} onPick={(v) => patch({ GrePtype: v })} />
          ) : null}
          {form.RawProfileDown === 'gre' ? (
            <PtypePick
              key={'down' + form.Srv}
              dir="down"
              value={form.GrePtypeDown}
              onPick={(v) => patch({ GrePtypeDown: v })}
            />
          ) : null}
          <div className="fldhint">{T('raw_ptype_hint')}</div>
        </div>
      </Reveal>
    </div>
  )
}
