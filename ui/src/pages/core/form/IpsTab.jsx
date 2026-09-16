import Select from '../../../components/Select.jsx'
import { Seg2, SegOpt, TglBox } from './controls.jsx'
import RotIpPool, { IpField } from './RotIpPool.jsx'
import PeerLive from './PeerLive.jsx'
import { rotIntervalItems } from './presets.js'
import { rotMulti } from './gates.js'
import { nodeLabel, seedIp } from './state.js'
import { toast } from '../../../lib/toast.js'
import { T } from '../../../i18n/fa.js'

function Side({ form, side, ips, stored, patch }) {
  const isServer = side === 'a' ? form.Srv === 'a' : form.Srv !== 'a'
  const label = isServer ? T('dst_ip') : T('src_ip')
  const selKey = side === 'a' ? 'aSel' : 'bSel'
  const ipKey = side === 'a' ? 'aIp' : 'bIp'

  if (form.rot.on && ips.length > 1) {
    return (
      <div style={{ order: isServer ? 0 : 1 }}>
        <RotIpPool
          label={label}
          ips={ips}
          selected={form.rot[selKey]}
          onToggle={(ip, count) => {
            const selected = { ...form.rot[selKey] }
            if (selected[ip]) {
              if (count <= 2) {
                toast(T('rot_min2'), 'err')
                return
              }
              delete selected[ip]
            } else selected[ip] = true
            patch({ rot: { ...form.rot, [selKey]: selected } })
          }}
        />
      </div>
    )
  }

  return (
    <div style={{ order: isServer ? 0 : 1 }}>
      <IpField
        label={label}
        ips={ips}
        value={seedIp(ips, form[ipKey], stored)}
        onChange={(v) => patch({ [ipKey]: v })}
      />
      {form.rot.on && !ips.length ? (
        <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>
          {T('rot_ips_unknown')}
        </div>
      ) : null}
    </div>
  )
}

export default function IpsTab({
  form,
  cfg,
  items,
  aIps,
  bIps,
  storedA,
  storedB,
  subtitle,
  peer,
  tuning,
  patch,
  onNode,
}) {
  const serverIsA = form.Srv === 'a'
  const aName = nodeLabel(items, form.aNode)
  const bName = nodeLabel(items, form.bNode)
  const multi = rotMulti(form, cfg.enums, aIps, bIps)

  return (
    <>
      {subtitle ? (
        <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
          <span className="mono">{subtitle}</span>
        </div>
      ) : null}

      <div className="grid2">
        <div style={{ order: serverIsA ? 0 : 1 }}>
          <label className="first">{serverIsA ? T('srv_node') : T('cli_node')}</label>
          <Select
            items={items}
            value={form.aNode}
            placeholder={T('srv_node')}
            onChange={(v) => onNode('a', v)}
          />
        </div>
        <div style={{ order: serverIsA ? 1 : 0 }}>
          <label className="first">{serverIsA ? T('cli_node') : T('srv_node')}</label>
          <Select
            items={items}
            value={form.bNode}
            placeholder={T('cli_node')}
            onChange={(v) => onNode('b', v)}
          />
        </div>
      </div>

      <div className="grid2" style={{ marginTop: 11 }}>
        <Side form={form} side="a" ips={aIps} stored={storedA} patch={patch} />
        <Side form={form} side="b" ips={bIps} stored={storedB} patch={patch} />
      </div>

      {multi ? (
        <TglBox
          on={form.rot.on}
          title={T('rot_t')}
          note={T('rot_d')}
          gap={12}
          onClick={() => patch({ rot: { ...form.rot, on: !form.rot.on } })}
        />
      ) : null}
      {multi && form.rot.on ? (
        <div style={{ marginTop: 2 }}>
          <label className="first">{T('rot_interval')}</label>
          <Select
            items={rotIntervalItems()}
            value={form.rot.secs}
            placeholder={T('rot_interval')}
            onChange={(v) => patch({ rot: { ...form.rot, secs: +v } })}
          />
        </div>
      ) : null}

      {peer ? <PeerLive live={peer} tuning={tuning} /> : null}

      <label>{T('roles_lbl')}</label>
      <Seg2>
        <SegOpt
          on={serverIsA}
          title={aName + ' ' + T('role_server_word')}
          sub={bName + ' ' + T('role_client_word')}
          onClick={() => patch({ Srv: 'a' })}
        />
        <SegOpt
          on={!serverIsA}
          title={bName + ' ' + T('role_server_word')}
          sub={aName + ' ' + T('role_client_word')}
          onClick={() => patch({ Srv: 'b' })}
        />
      </Seg2>
    </>
  )
}
