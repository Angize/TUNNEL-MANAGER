import RichText from '../../../components/RichText.jsx'
import Select from '../../../components/Select.jsx'
import { ScrollSeg, SegOpt, TglBox, Tile, Tiles } from './controls.jsx'
import ProtoSection from './ProtoSection.jsx'
import PortSection from './PortSection.jsx'
import BandSection from './BandSection.jsx'
import PortTriesSection from './PortTriesSection.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsSection from './WsSection.jsx'
import WsToggleRows from './WsToggleRows.jsx'
import FecSection from './FecSection.jsx'
import DesyncSection from './DesyncSection.jsx'
import { coverOk, wsPoolOn } from './gates.js'
import { TRANSPORTS, cipherItems, rawProfiles } from './presets.js'
import { PORT_MAX, rangeLabel } from '../../../lib/form.js'
import { subnetForBase, subnetRangeItems } from '../../../lib/subnet.js'
import { T } from '../../../i18n/fa.js'

function SubnetExtra({ form, link, patch }) {
  if (form.range === 'custom') {
    return (
      <div>
        <label>{T('custom_subnet')}</label>
        <input
          className={link ? 'mono' : undefined}
          placeholder={link ? undefined : T('ph_subnet')}
          value={form.subnet}
          onChange={(e) => patch({ subnet: e.target.value })}
        />
      </div>
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
      <label>{T('enc_method_lbl')}</label>
      <Select
        items={ciphers}
        value={form.cipher}
        placeholder={T('cipher_ph')}
        onChange={(v) => patch({ cipher: v })}
      />

      <label>{T('transport_lbl')}</label>
      <ScrollSeg>
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

      {form.Tr === 'raw' ? (
        <div>
          <label>{T('raw_prof_lbl')}</label>
          <Tiles>
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
          <PortSection form={form} enums={cfg.enums} patch={patch} />
        </div>
      ) : null}

      {form.Tr === 'raw' ? null : (
        <>
          {wsPoolOn(form) ? (
            <TglBox
              on={!!form.pool.portRoll}
              title={T('pool_roll_t')}
              note={T('pool_roll_d')}
              gap={11}
              onClick={() => patch({ pool: { ...form.pool, portRoll: !form.pool.portRoll } })}
            />
          ) : null}
          <PortTriesSection form={form} enums={cfg.enums} patch={patch} />
          <BandSection form={form} enums={cfg.enums} patch={patch} />
        </>
      )}
      <WorkersSection form={form} cfg={cfg} sides={sides} patch={patch} />
      <WsSection
        form={form}
        cfg={cfg}
        lid={poolLive.lid}
        live={poolLive}
        patch={patch}
      />

      <TglBox
        on={form.Obfs}
        title={T('obfs_t')}
        note={T('obfs_d')}
        hidden={form.cipher === 'none'}
        onClick={() => patch({ Obfs: !form.Obfs })}
      />
      <TglBox
        on={form.Cover}
        title={T('cover_t')}
        note={T('cover_d')}
        hidden={!coverOk(form)}
        onClick={() => patch({ Cover: !form.Cover })}
      />

      <WsToggleRows form={form} cfg={cfg} proxies={proxies} patch={patch} />

      {form.Cover && form.Tr === 'tcp' ? (
        <div>
          <label>{T('cover_sni_lbl')}</label>
          <input
            placeholder={T('cover_sni_ph')}
            value={form.coverSni}
            onChange={(e) => patch({ coverSni: e.target.value })}
          />
          <div className="muted" style={{ fontSize: 11, marginTop: 5, lineHeight: 1.7 }}>
            <RichText text={T('cover_sni_note')} />
          </div>
        </div>
      ) : null}

      <TglBox
        on={form.Gso}
        title={T('gso_t')}
        note={T('gso_d')}
        onClick={() => patch({ Gso: !form.Gso })}
      />

      <FecSection form={form} patch={patch} />
      <DesyncSection form={form} patch={patch} />

      <label>{T('core_range_lbl')}</label>
      <Select
        items={subnetRangeItems(subnetFree)}
        value={form.range}
        placeholder={T('range')}
        onChange={(v) => patch({ range: v })}
      />
      <SubnetExtra form={form} link={link} patch={patch} />

      {form.Tr === 'raw' ? null : (
        <div>
          <label>
            {rangeLabel(T(link ? 'core_port_lbl2' : 'core_port_lbl'), 1, PORT_MAX)}
          </label>
          <input
            inputMode="numeric"
            placeholder={T(form.Tr === 'ws' ? 'port_ws_ph' : 'port_band_ph')}
            value={form.port}
            onChange={(e) => patch({ port: e.target.value, portAuto: false })}
          />
        </div>
      )}

      {link ? (
        <div className="muted" style={{ fontSize: 11, margin: '2px 2px 0' }}>
          {T('core_edit_note')}
        </div>
      ) : null}
    </>
  )
}
