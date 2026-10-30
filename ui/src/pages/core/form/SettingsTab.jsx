import Field from '../../../components/Field.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import NumberInput from '../../../components/NumberInput.jsx'
import Select from '../../../components/Select.jsx'
import { ScrollSeg, SegOpt, WarnCap } from './controls.jsx'
import RawDirGrid from './RawDirGrid.jsx'
import ProtoSection from './ProtoSection.jsx'
import PortSection from './PortSection.jsx'
import BandSection from './BandSection.jsx'
import PortTriesSection from './PortTriesSection.jsx'
import WorkersSection from './WorkersSection.jsx'
import WsSection from './WsSection.jsx'
import WsToggleRows from './WsToggleRows.jsx'
import FecSection from './FecSection.jsx'
import DesyncSection from './DesyncSection.jsx'
import CdnPortRules from './CdnPortRules.jsx'
import { coverOk, wkCarrier } from './gates.js'
import Icon from '../../../components/Icon.jsx'
import { TRANSPORTS, cipherItems } from './presets.js'
import { portErr } from './validate.js'
import { LTR_TEXT, rangeLabel } from '../../../lib/form.js'
import { cdnAuto } from '../../../lib/cdn.js'
import { T, TF } from '../../../i18n/fa.js'

function RouteChip({ form, fronts, onRoute }) {
  const names = form.edges.map((e) => ((fronts || []).find((f) => f.id === e.node) || {}).name).filter(Boolean)
  return (
    <button type="button" className="routechip" onClick={onRoute}>
      <Icon name="swap" />
      <span>{TF('pedge_chip', { n: names.join('، ') })}</span>
      <em>{T('pedge_chip_go')}</em>
    </button>
  )
}

export default function SettingsTab({
  form,
  cfg,
  link,
  proxies,
  sides,
  poolLive,
  cdnKeys,
  serverIp,
  portRules,
  cdnOwners,
  onCdnMade,
  onRoute,
  patch,
}) {
  const ciphers = cipherItems(cfg.enums, form.Tr)
  const portError = portErr(form.port, cfg.limits)

  return (
    <>
      {form.EdgeOn ? <RouteChip form={form} fronts={cdnKeys && cdnKeys.fronts} onRoute={onRoute} /> : null}
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
          <RawDirGrid form={form} cfg={cfg} sides={sides} patch={patch} />
          <ProtoSection form={form} enums={cfg.enums} patch={patch} />
          <PortSection form={form} cfg={cfg} patch={patch} />
        </div>
      </Reveal>

      <Reveal show={form.Tr !== 'raw'}>
        <>
          <Reveal show={form.Tr === 'ws'}>
            <SwitchRow
              on={form.PortRoll}
              title={T('ws_roll_t')}
              note={T('ws_roll_d')}
              onToggle={() => patch({ PortRoll: !form.PortRoll })}
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
        cdnKeys={cdnKeys}
        serverIp={serverIp}
        cdnOwners={cdnOwners}
        onCdnMade={onCdnMade}
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
        <Field label={T('cover_sni_lbl')} hint={T('cover_sni_note')}>
          <input
            {...LTR_TEXT}
            placeholder={T('cover_sni_ph')}
            value={form.coverSni}
            onChange={(e) => patch({ coverSni: e.target.value })}
          />
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

      <Reveal show={form.Tr !== 'raw'}>
        <Field
          label={rangeLabel(T('core_port_lbl'), ...cfg.limits.port)}
          hint={form.Tr !== 'ws' ? T(link ? 'core_port_hint_edit' : 'core_port_hint') : null}
        >
          <NumberInput
            placeholder={T(form.Tr !== 'ws' ? 'port_band_ph' : !cdnAuto(form) ? 'port_ws_ph' : 'cdn_port_ph')}
            value={form.port}
            onChange={(v) => patch({ port: v, portAuto: false })}
          />
          <WarnCap text={portError} style={{ marginTop: 8 }} />
          <CdnPortRules
            infos={portRules}
            port={form.port}
            tls={!!form.WsTls}
            bad={!!portError}
            onPick={(v) => patch({ port: v, portAuto: false })}
          />
        </Field>
      </Reveal>

      {link ? <div className="fldhint">{T('core_edit_note')}</div> : null}
    </>
  )
}
