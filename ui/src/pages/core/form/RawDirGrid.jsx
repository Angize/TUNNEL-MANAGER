import Icon from '../../../components/Icon.jsx'
import { ctbDefault } from './gates.js'
import { rawProfiles } from './presets.js'
import { ptypeValid } from './ptype.js'
import { T } from '../../../i18n/fa.js'

const PTYPE_PRESETS = ['ffff', '8847']

function PtypePick({ dir, value, onPick }) {
  const up = dir === 'up'
  const custom = value !== '' && !PTYPE_PRESETS.includes(value)
  const bad = !ptypeValid(value)
  return (
    <div className={'ptyperow ' + dir}>
      <span className="ptypedir">
        <Icon name={up ? 'upload' : 'download'} />
        {T(up ? 'raw_dir_up' : 'raw_dir_down')}
      </span>
      <div className="ptypeopts" role="group">
        <button
          type="button"
          className={'ptypechip' + (value === '' ? ' on' : '')}
          aria-pressed={value === ''}
          onClick={() => onPick('')}
        >
          {T(up ? 'raw_ptype_def' : 'raw_ptype_same')}
        </button>
        {PTYPE_PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className={'ptypechip' + (value === p ? ' on' : '')}
            aria-pressed={value === p}
            onClick={() => onPick(p)}
          >
            {T(p === 'ffff' ? 'raw_ptype_ffff' : 'raw_ptype_mpls')}
          </button>
        ))}
        <span className="ptypehexwrap">
          <span className="pre">0x</span>
          <input
            className={'ptypehex' + (custom ? ' on' : '') + (bad ? ' bad' : '')}
            value={custom ? value : ''}
            maxLength={4}
            dir="ltr"
            inputMode="latin"
            placeholder={T('raw_ptype_custom_ph')}
            aria-label={T('raw_ptype_custom')}
            onChange={(e) => onPick(e.target.value.toLowerCase().replace(/[^0-9a-f]/g, '').slice(0, 4))}
          />
        </span>
      </div>
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
      {form.RawProfile === 'gre' || form.RawProfileDown === 'gre' ? (
        <div className="greptype">
          <label>{T('raw_ptype_lbl')}</label>
          {form.RawProfile === 'gre' ? (
            <PtypePick dir="up" value={form.GrePtype} onPick={(v) => patch({ GrePtype: v })} />
          ) : null}
          {form.RawProfileDown === 'gre' ? (
            <PtypePick dir="down" value={form.GrePtypeDown} onPick={(v) => patch({ GrePtypeDown: v })} />
          ) : null}
          <div className="fldhint">{T('raw_ptype_hint')}</div>
        </div>
      ) : null}
    </div>
  )
}
