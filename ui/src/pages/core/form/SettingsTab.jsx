import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import RichText from '../../../components/RichText.jsx'
import Select from '../../../components/Select.jsx'
import { ScrollSeg, SegOpt, Tile, Tiles, WarnCap } from './controls.jsx'
import ProtoSection from './ProtoSection.jsx'
import PortSection from './PortSection.jsx'
import BandSection from './BandSection.jsx'
import PortTriesSection from './PortTriesSection.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsSection from './WsSection.jsx'
import WsToggleRows from './WsToggleRows.jsx'
import FecSection from './FecSection.jsx'
import DesyncSection from './DesyncSection.jsx'
import { coverOk, wkCarrier, wsPoolOn } from './gates.js'
import { TRANSPORTS, cipherItems, rawProfiles } from './presets.js'
import { portErr } from './validate.js'
import { NO_AUTOFIX, rangeLabel } from '../../../lib/form.js'
import { subnetForBase, subnetRangeItems } from '../../../lib/subnet.js'
import { T } from '../../../i18n/fa.js'

function SubnetExtra({ form, link, patch }) {
  if (form.range === 'custom') {
    return (
      <Field label={T('custom_subnet')}>
        <input
          className={link ? 'mono' : undefined}
          {...NO_AUTOFIX}
          placeholder={link ? undefined : T('ph_subnet')}
          value={form.subnet}
          onChange={(e) => patch({ subnet: e.target.value })}
        />
      </Field>
    )
  }
  if (!link) return null
  return (
    <div className="muted" style={{ fontSize: 11, margin: '6px 2px 0' }}>
      {T('core_subnet_lbl') + ': '}
      <b className="mono">{subnetForBase(link.type, link.tunnel_id, form.range) || '—'}</b>
    </div>
  )
}

export default function SettingsTab({
  form,
  cfg,
  link,
  proxies,
  sides,
  subnetFree,
  poolLive,
  patch,
}) {
  const ciphers = cipherItems(cfg.enums, form.Tr)

  return (
    <>
      <Field label={T('enc_method_lbl')}>
        <Select
          items={ciphers}
          value={form.cipher}
          placeholder={T('cipher_ph')}
          onChange={(v) => patch({ cipher: v })}
        />
      </Field>

      <label>{T('transport_lbl')}</label>
      <ScrollSeg label={T('transport_lbl')}>
        {TRANSPORTS.map((tr) => (
          <SegOpt
            key={tr.v}
            on={form.Tr === tr.v}
            title={tr.n}
            sub={T(tr.d)}
            onClick={() => patch({ Tr: tr.v })}
          />
        ))}
      </ScrollSeg>

      <Reveal show={form.Tr === 'raw'}>
        <div>
          <label>{T('raw_prof_lbl')}</label>
          <Tiles label={T('raw_prof_lbl')}>
            {rawProfiles().map((profile) => (
              <Tile
                key={profile.v}
                on={profile.v === form.RawProfile}
                name={profile.v}
                meta={profile.m}
                onClick={() => patch({ RawProfile: profile.v })}
              />
            ))}
          </Tiles>
          <ProtoSection form={form} enums={cfg.enums} patch={patch} />
          <PortSection form={form} cfg={cfg} patch={patch} />
        </div>
      </Reveal>

      <Reveal show={form.Tr !== 'raw'}>
        <>
          <Reveal show={wsPoolOn(form)}>
            <SwitchRow
              on={!!form.pool.portRoll}
              title={T('pool_roll_t')}
              note={T('pool_roll_d')}
              onToggle={() => patch({ pool: { ...form.pool, portRoll: !form.pool.portRoll } })}
            />
          </Reveal>
          <PortTriesSection form={form} cfg={cfg} patch={patch} />
          <BandSection form={form} cfg={cfg} patch={patch} />
        </>
      </Reveal>
      <Reveal show={wkCarrier(form) && form.Tr !== 'ws'}>
        <WorkersSection form={form} cfg={cfg} sides={sides} patch={patch} />
      </Reveal>
      <WsSection
        form={form}
        cfg={cfg}
        sides={sides}
        lid={poolLive.lid}
        live={poolLive}
        patch={patch}
      />

      <Reveal show={form.cipher !== 'none'}>
        <SwitchRow
          on={form.Obfs}
          title={T('obfs_t')}
          note={T('obfs_d')}
          onToggle={() => patch({ Obfs: !form.Obfs })}
        />
      </Reveal>
      <Reveal show={coverOk(form)}>
        <SwitchRow
          on={form.Cover}
          title={T('cover_t')}
          note={T('cover_d')}
          onToggle={() => patch({ Cover: !form.Cover })}
        />
      </Reveal>

      <WsToggleRows form={form} cfg={cfg} proxies={proxies} patch={patch} />

      <Reveal show={form.Cover && form.Tr === 'tcp'}>
        <Field label={T('cover_sni_lbl')}>
          <input
            {...NO_AUTOFIX}
            placeholder={T('cover_sni_ph')}
            value={form.coverSni}
            onChange={(e) => patch({ coverSni: e.target.value })}
          />
          <div className="muted" style={{ fontSize: 11, marginTop: 5, lineHeight: 1.7 }}>
            <RichText text={T('cover_sni_note')} />
          </div>
        </Field>
      </Reveal>

      <SwitchRow
        on={form.Gso}
        title={T('gso_t')}
        note={T('gso_d')}
        onToggle={() => patch({ Gso: !form.Gso })}
      />

      <FecSection form={form} patch={patch} />
      <DesyncSection form={form} limits={cfg.limits} patch={patch} />

      <Field label={T('core_range_lbl')}>
        <Select
          items={subnetRangeItems(subnetFree)}
          value={form.range}
          placeholder={T('range')}
          onChange={(v) => patch({ range: v })}
        />
      </Field>
      <SubnetExtra form={form} link={link} patch={patch} />

      <Reveal show={form.Tr !== 'raw'}>
        <Field
          label={rangeLabel(T(link ? 'core_port_lbl2' : 'core_port_lbl'), ...cfg.limits.port)}
        >
          <NumberInput
            placeholder={T(form.Tr === 'ws' ? 'port_ws_ph' : 'port_band_ph')}
            value={form.port}
            onChange={(v) => patch({ port: v, portAuto: false })}
          />
          <WarnCap text={portErr(form.port, cfg.limits)} style={{ marginTop: 8 }} />
        </Field>
      </Reveal>

      {link ? (
        <div className="muted" style={{ fontSize: 11, margin: '2px 2px 0' }}>
          {T('core_edit_note')}
        </div>
      ) : null}
    </>
  )
}
