import { useId } from 'react'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import Field from '../../../components/Field.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import Stepper from '../../../components/Stepper.jsx'
import { Seg2, SegOpt, WarnCap } from './controls.jsx'
import { ctbOn, rawPortOn, sprotLive } from './gates.js'
import PortTriesSection from './PortTriesSection.jsx'
import BandSection from './BandSection.jsx'
import { RAW_DPORTS_MAX, RAW_SPROT_MAX, SPROT_DEFAULT } from './presets.js'
import { intOf, sprotErr } from './validate.js'
import { rangeLabel } from '../../../lib/form.js'
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

function SourcePort({ form, limits, patch }) {
  const id = useId()
  const locked = sprotLive(form)
  const current = intOf(form.rawSport)
  const presets = SPORT_PRESETS[form.RawProfile]
  const label = rangeLabel(T('raw_sport_lbl'), ...limits.port)

  return (
    <div className={locked ? 'portlock' : undefined} inert={locked}>
      <label htmlFor={form.SportRandom ? undefined : id}>{label}</label>
      <Seg2 label={label}>
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
      <Reveal show={!form.SportRandom}>
        <div style={{ marginTop: 8 }}>
          {presets.length ? (
            <Seg2 label={label} style={{ marginBottom: 8 }}>
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
          <NumberInput
            id={id}
            className="mono"
            maxLength={5}
            placeholder={String(RAW_SPORT_FIXED)}
            style={{ textAlign: 'center', direction: 'ltr' }}
            value={form.rawSport}
            onChange={(v) => patch({ rawSport: v })}
          />
        </div>
      </Reveal>
    </div>
  )
}

function SportRotation({ form, patch }) {
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
      <SwitchRow on={live} title={T('raw_sprot_t')} note={T('raw_sprot_d')} onToggle={toggle} />
      <Reveal show={live}>
        <div>
          <div className="grid2">
            <Field label={rangeLabel(T('raw_sprot_lbl'), 1, RAW_SPROT_MAX)}>
              <Stepper
                min={1}
                max={RAW_SPROT_MAX}
                placeholder={String(SPROT_DEFAULT)}
                value={form.rawSprot}
                onChange={(v) => patch({ rawSprot: v })}
              />
            </Field>
            <Field label={rangeLabel(T('raw_dports_lbl'), 1, RAW_DPORTS_MAX)}>
              <Stepper
                min={1}
                max={RAW_DPORTS_MAX}
                placeholder="1"
                value={form.rawDports}
                onChange={(v) => patch({ rawDports: v })}
              />
            </Field>
          </div>
          <WarnCap text={sprotErr(form)} style={{ marginTop: 8 }} />
        </div>
      </Reveal>
    </div>
  )
}

function RawPort({ form, cfg, patch }) {
  const id = useId()
  const current = intOf(form.rawPort)
  const label = rangeLabel(T('raw_port_lbl'), ...cfg.limits.port)
  const draws = (
    <>
      <PortTriesSection form={form} cfg={cfg} patch={patch} />
      <BandSection form={form} cfg={cfg} patch={patch} />
    </>
  )

  return (
    <div style={{ marginTop: 12 }}>
      <label className="first" htmlFor={id}>
        {label}
      </label>
      <Seg2 label={label} style={{ marginBottom: 8 }}>
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
      <NumberInput
        id={id}
        className="mono"
        maxLength={5}
        placeholder="443"
        style={{ textAlign: 'center', direction: 'ltr' }}
        value={form.rawPort}
        onChange={(v) => patch({ rawPort: v })}
      />
      <SourcePort form={form} limits={cfg.limits} patch={patch} />
      <Reveal show={form.SportRandom}>{draws}</Reveal>
      <SportRotation form={form} patch={patch} />
      <Reveal show={!form.SportRandom}>{draws}</Reveal>
      <Reveal show={ctbOn(form, cfg.enums)}>
        <SwitchRow
          on={!!form.Ctb}
          title={T('ctb_t')}
          note={T('ctb_d')}
          onToggle={() => patch({ Ctb: !form.Ctb })}
        />
      </Reveal>
    </div>
  )
}

export default function PortSection(props) {
  return (
    <Reveal show={rawPortOn(props.form)}>
      <RawPort {...props} />
    </Reveal>
  )
}
