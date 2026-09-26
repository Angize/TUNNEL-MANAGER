import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import RichText from '../../components/RichText.jsx'
import { modeLabel } from './ModePicker.jsx'
import { FIELDS, secondsToMinutes } from './tuning.js'
import { T, TF } from '../../i18n/fa.js'

const COUNTS = [
  ['bk_r_nodes', 'nodes'],
  ['bk_r_core', 'core'],
  ['bk_r_system', 'system'],
  ['bk_r_proxies', 'proxies'],
  ['bk_r_events', 'events'],
]

const LABELS = {
  reconcile_mode: 'set_on_ipchange',
  reconcile_interval: 'set_rec_int',
  poll_interval: 'set_poll_int',
  ui_interval: 'set_ui_int',
  ech_refresh_mins: 'set_ech_int',
  uptime_window: 'set_upwin',
  api_external: 'set_api_on',
  api_token_hash: 'set_api_token',
  agent_delivery: 'bk_s_agent',
  core_delivery: 'bk_s_core',
  dl_proxy_on: 'dlpx_on',
  dl_proxy_id: 'bk_s_dlpx',
  log_hidden: 'bk_s_hidden',
  'tuning.probe_min_pct': 'set_t_probemin',
  'tuning.ladder_revive': 'set_t_revive',
  'tuning.suspect_backoff': 'set_t_suspect',
  'tuning.dead_retest_secs': 'set_t_deadretest',
  'tuning.sock_buf_mb': 'set_t_sockbuf',
  'tuning.tcp_buf_mb': 'set_t_tcpbuf',
}

const UNITS = Object.fromEntries(
  Object.values(FIELDS).map((f) => [f.setting || 'tuning.' + f.tuning, f.unitKey]),
)

const DELIVERY = { push: 'dlv_push_t', github: 'dlv_git_t', panel: 'dlv_pan_t' }

function madeAt(ts) {
  if (!ts) return T('bk_when_unknown')
  return new Date(ts * 1000).toLocaleString('fa-IR-u-nu-latn', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function shown(key, v) {
  if (v == null || v === '') return T('bk_none')
  if (key === 'reconcile_mode') return modeLabel(v)
  if (key === 'agent_delivery' || key === 'core_delivery') return DELIVERY[v] ? T(DELIVERY[v]) : String(v)
  if (key === 'uptime_window') return T('h' + v)
  if (key === 'log_hidden') return v.length ? TF('bk_kinds', { n: v.length }) : T('bk_none')
  if (key === 'tuning.suspect_backoff') return v.map(secondsToMinutes).join('، ')
  if (key === 'tuning.dead_retest_secs') return String(secondsToMinutes(v))
  if (typeof v === 'boolean') return T(v ? 'bk_on' : 'bk_off')
  if (Array.isArray(v)) return v.join('، ')
  return String(v)
}

function withUnit(key, v) {
  const text = shown(key, v)
  return UNITS[key] && v != null && v !== '' ? text + ' ' + T(UNITS[key]) : text
}

const ORDER = Object.keys(LABELS)

function rank(key) {
  const i = ORDER.indexOf(key)
  return i < 0 ? ORDER.length : i
}

export default function RestoreConfirm({ info, busy, onRestore, onClose }) {
  const changed = [...info.settings.changed].sort((a, b) => rank(a.key) - rank(b.key))
  const rest = info.settings.total - changed.length

  const footer = (
    <>
      <button className="primary bkgo" disabled={busy} onClick={onRestore}>
        {busy ? (
          <span className="bspin" />
        ) : (
          <>
            <Icon name="upload" />
            {T('bk_go')}
          </>
        )}
      </button>
      <button className="ghost" disabled={busy} onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon="upload"
      title={T('bk_title')}
      subtitle={TF('bk_sub', { when: madeAt(info.made) })}
      footer={footer}
      onClose={busy ? () => {} : onClose}
    >
      <div className="bkcmp">
        <span />
        <span>{T('bk_now')}</span>
        <span>{T('bk_after')}</span>
        {COUNTS.map(([label, key]) => [
          <span key={key + 'l'}>{T(label)}</span>,
          <span key={key + 'a'}>{info.now[key]}</span>,
          <span key={key + 'b'} className={info.now[key] !== info.after[key] ? 'bkch' : ''}>
            {info.after[key]}
          </span>,
        ])}
      </div>

      {info.portfw ? (
        <p className="bknote">
          <Icon name="info" />
          <span>{TF('bk_portfw', { n: info.portfw })}</span>
        </p>
      ) : null}

      <div className="bksec">
        {changed.length ? TF('bk_set_head', { n: changed.length, t: info.settings.total }) : T('bk_set_none')}
      </div>
      {changed.length ? (
        <div className="bkset">
          {changed.map((c) => (
            <div className="bkrow" key={c.key}>
              <span>{T(LABELS[c.key] || c.key)}</span>
              <span className="bkval">
                {c.secret ? (
                  T('bk_secret')
                ) : (
                  <>
                    <bdi>{withUnit(c.key, c.old)}</bdi>
                    {'  ←  '}
                    <bdi>{withUnit(c.key, c.new)}</bdi>
                  </>
                )}
              </span>
            </div>
          ))}
        </div>
      ) : null}
      <p className="bknote">
        <span>
          {(changed.length && rest ? TF('bk_set_rest', { n: rest }) + ' ' : '') +
            T(info.same_key ? 'bk_key_same' : 'bk_key_other')}
        </span>
      </p>

      <div className="bkwarn">
        <RichText text={T('bk_warn')} />
        <code>systemctl disable --now tnl-central</code>
      </div>
    </Modal>
  )
}
