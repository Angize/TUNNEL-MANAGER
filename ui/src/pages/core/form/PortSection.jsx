import { Seg2, SegOpt, TglBox, WarnCap } from './controls.jsx'
import { rawPortOn, sprotLive, sprotOn } from './gates.js'
import { RAW_DPORTS_MAX, RAW_SPROT_MAX, SPROT_DEFAULT } from './presets.js'
import { intOf, sprotErr } from './validate.js'
import { PORT_MAX, rangeLabel } from '../../../lib/form.js'
import { RAW_SPORT_FIXED } from '../carrier.js'
import { T } from '../../../i18n/fa.js'

const DPORT_PRESETS = {
  udp: [
    { v: 443, sub: () => T('raw_port_quic') },
    { v: 51820, sub: () => 'WireGuard' },
    { v: 4500, sub: () => 'IPsec' },
  ],
  tcp: [
    { v: 443, sub: () => 'HTTPS' },
    { v: 80, sub: () => 'HTTP' },
    { v: 8443, sub: () => 'HTTPS-alt' },
  ],
}

const SPORT_PRESETS = {
  udp: [
    { v: 51820, sub: () => 'WireGuard' },
    { v: 4500, sub: () => 'IPsec' },
    { v: 500, sub: () => T('raw_sport_ike') },
  ],
  tcp: [],
}

function SourcePort({ form, patch }) {
  const locked = sprotLive(form)
  const current = parseInt(form.rawSport, 10)
  const presets = SPORT_PRESETS[form.RawProfile]

  return (
    <div className={locked ? 'portlock' : undefined} inert={locked}>
      <label style={{ marginTop: 13 }}>{rangeLabel(T('raw_sport_lbl'), 1, PORT_MAX)}</label>
      <Seg2>
        <SegOpt
          on={!form.SportRandom}
          title={T('raw_sport_fixed_n')}
          sub={T('raw_sport_fixed_m')}
          onClick={() => patch({ SportRandom: false })}
        />
        <SegOpt
          on={form.SportRandom}
          title={T('raw_sport_rand_n')}
          sub={T('raw_sport_rand_m')}
          onClick={() => patch({ SportRandom: true })}
        />
      </Seg2>
      {form.SportRandom ? null : (
        <div style={{ marginTop: 8 }}>
          {presets.length ? (
            <Seg2 style={{ marginBottom: 8 }}>
              {presets.map((preset) => (
                <SegOpt
                  key={preset.v}
                  on={current === preset.v}
                  title={String(preset.v)}
                  sub={preset.sub()}
                  onClick={() => patch({ rawSport: String(preset.v) })}
                />
              ))}
            </Seg2>
          ) : null}
          <input
            className="mono"
            inputMode="numeric"
            maxLength={5}
            placeholder={String(RAW_SPORT_FIXED)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.rawSport}
            onChange={(e) => patch({ rawSport: e.target.value })}
          />
        </div>
      )}
    </div>
  )
}

function SportRotation({ form, patch }) {
  if (!sprotOn(form)) return null
  const live = sprotLive(form)

  const toggle = () => {
    if (live) {
      patch({ Sprot: false })
      return
    }
    const next = { Sprot: true, SportRandom: false }
    if (!intOf(form.rawSprot)) next.rawSprot = String(SPROT_DEFAULT)
    patch(next)
  }

  return (
    <div>
      <TglBox on={live} title={T('raw_sprot_t')} note={T('raw_sprot_d')} onClick={toggle} />
      {live ? (
        <div>
          <div className="grid2">
            <div>
              <label>{rangeLabel(T('raw_sprot_lbl'), 1, RAW_SPROT_MAX)}</label>
              <input
                className="mono"
                inputMode="numeric"
                maxLength={2}
                placeholder={String(SPROT_DEFAULT)}
                style={{ textAlign: 'center', direction: 'ltr' }}
                value={form.rawSprot}
                onChange={(e) => patch({ rawSprot: e.target.value })}
              />
            </div>
            <div>
              <label>{rangeLabel(T('raw_dports_lbl'), 1, RAW_DPORTS_MAX)}</label>
              <input
                className="mono"
                inputMode="numeric"
                maxLength={2}
                placeholder="1"
                style={{ textAlign: 'center', direction: 'ltr' }}
                value={form.rawDports}
                onChange={(e) => patch({ rawDports: e.target.value })}
              />
            </div>
          </div>
          <WarnCap text={sprotErr(form)} style={{ marginTop: 8 }} />
        </div>
      ) : null}
    </div>
  )
}

export default function PortSection({ form, patch }) {
  if (!rawPortOn(form)) return null
  const current = parseInt(form.rawPort, 10)

  return (
    <div style={{ marginTop: 11 }}>
      <label className="first">{rangeLabel(T('raw_port_lbl'), 1, PORT_MAX)}</label>
      <Seg2 style={{ marginBottom: 8 }}>
        {DPORT_PRESETS[form.RawProfile].map((preset) => (
          <SegOpt
            key={preset.v}
            on={current === preset.v}
            title={String(preset.v)}
            sub={preset.sub()}
            onClick={() => patch({ rawPort: String(preset.v) })}
          />
        ))}
      </Seg2>
      <input
        className="mono"
        inputMode="numeric"
        maxLength={5}
        placeholder="443"
        style={{ textAlign: 'center', direction: 'ltr' }}
        value={form.rawPort}
        onChange={(e) => patch({ rawPort: e.target.value })}
      />
      <SourcePort form={form} patch={patch} />
      <SportRotation form={form} patch={patch} />
    </div>
  )
}
