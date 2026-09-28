import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from '../../components/Icon.jsx'
import { Check } from '../../components/Marks.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import ProxyFields from '../../components/ProxyFields.jsx'
import Reveal from '../../components/Reveal.jsx'
import { HostKeyFix, Roll, StepIcon } from './InstallProgress.jsx'
import {
  autoName,
  endText,
  endTone,
  listCounts,
  parseList,
  prefixValid,
  resolveList,
  tally,
  targetText,
} from './bulk.js'
import SshAuth from './SshAuth.jsx'
import usePresence from '../../lib/usePresence.js'
import { reducedMotion } from '../../lib/motion.js'
import { apiGet } from '../../lib/api.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { useBulk } from '../../state/BulkInstallContext.jsx'
import { T, TF } from '../../i18n/fa.js'
import { LTR_TEXT, PORT_MAX, rangeLabel } from '../../lib/form.js'

export function useBulkList(bulk, listing) {
  const [known, setKnown] = useState([])
  const f = bulk.form

  useEffect(() => {
    if (!listing) return undefined
    let alive = true
    apiGet('nodes')
      .then((r) => {
        if (alive) setKnown(r.nodes)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [listing])

  const sharedAuth = f.authMode === 'pass' ? !!f.pass : !!f.key.trim()
  const parsed = useMemo(() => parseList(f.text), [f.text])
  const rows = useMemo(
    () => resolveList(parsed, { prefix: f.prefix, sharedAuth, nodes: known }),
    [parsed, f.prefix, sharedAuth, known]
  )
  return { rows, counts: listCounts(rows), prefixOk: prefixValid(f.prefix, parsed.length) }
}

function PreviewRow({ row, onJump }) {
  const ok = row.status === 'ok'
  const soft = row.status === 'no_auth'
  return (
    <button
      type="button"
      className={'bprow ' + (ok ? 'ok' : soft ? 'soft' : 'bad')}
      title={TF('nb_line', { n: row.line })}
      onClick={() => onJump(row.line)}
    >
      <span className="bpn">{row.line}</span>
      <span className="bpmid">
        {row.status === 'no_host' ? (
          <span className="bphost">
            <span className="bptx">{row.raw}</span>
          </span>
        ) : (
          <>
            <span className="bpname">
              {row.name}
              {row.auto ? <i className="bpauto">{T('nb_auto_name')}</i> : null}
            </span>
            <span className="bphost">
              <span className="bptx">{targetText(row)}</span>
              {row.pass ? (
                <span className="bpkey" title={T('nb_own_pass')}>
                  <Icon name="lock" />
                </span>
              ) : null}
            </span>
          </>
        )}
        {ok ? null : <span className="bpwhy">{T('nb_st_' + row.status)}</span>}
      </span>
      <span className="bpst">
        <Icon name={ok ? 'check' : 'warn'} />
      </span>
    </button>
  )
}

export function BulkForm({ bulk, list, proxies }) {
  const box = useRef(null)
  const parallel = useUiConfig().limits.install_parallel
  const { form, setForm, starting } = bulk
  const { rows, counts: c, prefixOk } = list
  const prefix = form.prefix.trim() || 'DE'

  const jump = (line) => {
    const el = box.current
    if (!el) return
    const lines = el.value.split('\n')
    let at = 0
    for (let i = 0; i < line - 1; i++) at += lines[i].length + 1
    el.focus()
    el.setSelectionRange(at, at + (lines[line - 1] || '').length)
    const lh = parseFloat(getComputedStyle(el).lineHeight) || 20
    el.scrollTop = Math.max(0, (line - 2) * lh)
  }

  return (
    <div>
      <div className="autonote">
        <Icon name="bolt" />
        <span>{TF('nb_note', { n: parallel })}</span>
      </div>

      <Field label={T('nb_list')} hint={T('nb_list_hint')} first>
        <textarea
          ref={box}
          className="blist"
          rows={6}
          {...LTR_TEXT}
          disabled={starting}
          placeholder={T('nb_ph')}
          value={form.text}
          onChange={(e) => setForm({ text: e.target.value })}
        />
      </Field>

      <Reveal show={rows.length > 0}>
        <div>
          <div className="bpsum">
            <b>{TF('nb_count', { n: c.all })}</b>
            {c.ok ? <span className="bchip ok">{TF('nb_ready', { n: c.ok })}</span> : null}
            {c.auth ? <span className="bchip warn">{TF('nb_wait_auth', { n: c.auth })}</span> : null}
            {c.bad ? <span className="bchip bad">{TF('nb_bad', { n: c.bad })}</span> : null}
          </div>
          <div className="bprev bcard">
            {rows.map((r) => (
              <PreviewRow key={r.line} row={r} onJump={jump} />
            ))}
          </div>
          {c.bad ? <div className="fldhint">{TF('nb_skip_n', { n: c.bad })}</div> : null}
        </div>
      </Reveal>

      <div className="bshared">
        <Icon name="cog" />
        {T('nb_shared')}
      </div>
      <div className="grid2">
        <Field label={T('nb_prefix')} error={prefixOk ? '' : T('nb_prefix_bad')}>
          <input {...LTR_TEXT} placeholder="DE" value={form.prefix} onChange={(e) => setForm({ prefix: e.target.value })} />
        </Field>
        <Field label={rangeLabel(T('nadd_agent_port'), 1, PORT_MAX)}>
          <NumberInput placeholder="8099" value={form.agentPort} onChange={(v) => setForm({ agentPort: v })} />
        </Field>
      </div>
      <div className="fldhint">
        <span>
          {T('nb_prefix_hint_a')}
          <bdi dir="ltr">{autoName(prefix, 1, rows.length)}</bdi>، <bdi dir="ltr">{autoName(prefix, 2, rows.length)}</bdi>،
          {T('nb_prefix_hint_b')}
        </span>
      </div>
      <div className="grid2">
        <Field label={rangeLabel(T('nadd_ssh_port'), 1, PORT_MAX)}>
          <NumberInput placeholder="22" value={form.sshPort} onChange={(v) => setForm({ sshPort: v })} />
        </Field>
        <Field label={T('nadd_ssh_user')}>
          <input {...LTR_TEXT} placeholder="root" value={form.sshUser} onChange={(e) => setForm({ sshUser: e.target.value })} />
        </Field>
      </div>

      <SshAuth
        mode={form.authMode}
        onMode={(m) => setForm({ authMode: m })}
        pass={form.pass}
        onPass={(v) => setForm({ pass: v })}
        sshKey={form.key}
        onKey={(v) => setForm({ key: v })}
        passHint={T('nb_auth_hint')}
        keyHint={T('nb_auth_hint')}
      />

      <ProxyFields proxies={proxies} value={form.proxy} onChange={(v) => setForm({ proxy: v })} />
    </div>
  )
}

function runStatus(row) {
  if (row.state === 'wait') return T('nb_q')
  if (row.state === 'ok') return T('nb_ok')
  if (row.state === 'warn') return T('nb_warn')
  if (row.state === 'stop') return T('nb_stopped')
  return row.step ? TF('nb_err_at', { s: row.step }) : T('nb_lost')
}

function RunRow({ row, index, onRetry }) {
  const [open, setOpen] = useState(false)
  const err = row.state === 'err'
  return (
    <div className={'brow ' + row.state} style={{ '--i': index }}>
      <button
        type="button"
        className="brhd"
        disabled={!err}
        aria-expanded={err ? (open ? 'true' : 'false') : undefined}
        title={err ? T('nb_show_log') : undefined}
        onClick={() => setOpen(!open)}
      >
        <StepIcon state={row.state === 'stop' ? 'wait' : row.state} />
        <span className="brb">
          <b>{row.name}</b>
          <span className="brh">{row.host}</span>
        </span>
        <span className="brs">
          {row.state === 'run' ? (
            <>
              <Roll text={row.step} />
              <span className="ibx">{TF('inst_step_of', { n: row.at, total: row.of })}</span>
            </>
          ) : (
            runStatus(row)
          )}
        </span>
        {err ? <Icon name="chev" /> : null}
      </button>
      {err ? (
        <Reveal show={open}>
          <div className="brlog">
            {row.detail ? <div className="istep-s">{row.detail}</div> : null}
            {row.log ? <div className="ilog">{row.log}</div> : null}
            {row.hostkey && onRetry ? (
              <HostKeyFix
                onFix={async () => {
                  const why = await onRetry(index)
                  if (why) alertBox(why)
                }}
              />
            ) : null}
          </div>
        </Reveal>
      ) : null}
    </div>
  )
}

export function BulkRun({ batch, onRetry }) {
  const top = useRef(null)
  const t = tally(batch.rows)
  const n = batch.rows.length
  const w = (k) => (100 * k) / Math.max(n, 1) + '%'
  const tone = batch.done ? endTone(t) : ''

  useEffect(() => {
    const body = top.current && top.current.closest('.mbody')
    if (body) body.scrollTo({ top: 0, behavior: reducedMotion() ? 'auto' : 'smooth' })
  }, [])

  return (
    <div ref={top}>
      <div className={'bsum bcard ' + tone} role="status">
        <div className="bsumhd">
          <b className="bsumn">{TF('nb_done_of', { d: t.end, n })}</b>
          {batch.done ? <span className="bsumtx">{T('nb_finished')}</span> : null}
          <span className="bchips">
            {[
              ['ok', 'check', t.ok],
              ['warn', 'warn', t.warn],
              ['bad', 'x', t.err],
              ['', 'pause', t.stop],
            ].map(([chip, icon, k]) =>
              k ? (
                <span key={icon} className={'bchip ' + chip}>
                  <Icon name={icon} />
                  {k}
                </span>
              ) : null
            )}
          </span>
        </div>
        <div className="bbar" aria-hidden="true">
          <i className="ok" style={{ width: w(t.ok) }} />
          <i className="warn" style={{ width: w(t.warn) }} />
          <i className="err" style={{ width: w(t.err) }} />
          <i className="stop" style={{ width: w(t.stop) }} />
          <i className="run" style={{ width: w(t.run) }} />
        </div>
        <div className="bsumsub">
          {batch.done ? endText(t) : TF('nb_running', { r: t.run, q: t.wait })}
        </div>
      </div>
      <div className="brun bcard">
        {batch.rows.map((r, i) => (
          <RunRow key={i} row={r} index={i} onRetry={onRetry} />
        ))}
      </div>
    </div>
  )
}

export function BulkFooter({ bulk, list, onClose }) {
  const { batch, starting } = bulk
  const t = batch ? tally(batch.rows) : null

  const install = async () => {
    const ready = list.rows.filter((r) => r.status === 'ok')
    if (!ready.length) {
      alertBox(list.counts.auth ? T('nb_need_auth') : T('nb_nothing'))
      return
    }
    const err = await bulk.start(ready)
    if (err) alertBox(err)
  }

  const stop = async () => {
    if (await confirmBox(T('nb_stop_q'), T('nb_stop_yes'))) bulk.stop()
  }

  if (!batch) {
    return (
      <>
        <button className="primary" disabled={starting} onClick={install}>
          {starting ? (
            <span className="bspin" />
          ) : (
            <>
              <Icon name="bolt" />
              {list.counts.ok ? TF('nb_install_n', { n: list.counts.ok }) : T('nb_fab')}
            </>
          )}
        </button>
        <button className="ghost" onClick={onClose}>
          {T('cancel')}
        </button>
      </>
    )
  }
  if (!batch.done) {
    return (
      <>
        <button className="primary glass" onClick={onClose}>
          {T('nb_bg')}
        </button>
        <button className="ghost tone tone-del" disabled={!t.wait || batch.stopped} onClick={stop}>
          <Icon name="pause" />
          {T('nb_stop')}
        </button>
      </>
    )
  }
  if (!t.bad) {
    return (
      <button className="primary done" onClick={onClose}>
        <Check /> {T('inst_done')}
      </button>
    )
  }
  return (
    <>
      <button className="primary" onClick={bulk.editFailed}>
        <Icon name="pen" />
        {TF('nb_fix', { n: t.bad })}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('inst_done')}
      </button>
    </>
  )
}

const TONE_ICON = { ok: 'check', mid: 'pause', bad: 'warn' }

function BulkFab({ batch, hidden, onOpen }) {
  const visible = !!batch && !hidden
  const shown = usePresence(visible, 180)
  const [kept, setKept] = useState(batch)
  if (visible && batch !== kept) setKept(batch)

  useEffect(() => {
    document.body.classList.toggle('bulking', visible)
    return () => document.body.classList.remove('bulking')
  }, [visible])

  const b = visible ? batch : kept
  if (!shown || !b) return null
  const t = tally(b.rows)
  const n = b.rows.length
  const tone = b.done ? endTone(t) : ''
  return createPortal(
    <button type="button" className={'bfab ' + tone + (visible ? '' : ' out')} inert={!visible} onClick={onOpen}>
      {b.done ? <Icon name={TONE_ICON[tone]} /> : <span className="ispin" />}
      <span>{b.done ? T('nb_fab_done') : T('nb_fab')}</span>
      <span className="bfn">
        {t.end}
        <s>/{n}</s>
      </span>
      <span className="bfbar">
        <i style={{ width: (100 * t.end) / Math.max(n, 1) + '%' }} />
      </span>
    </button>,
    document.body
  )
}

export function BulkFabHost({ onNavigate }) {
  const { batch, dialog, ask } = useBulk()
  return <BulkFab batch={batch} hidden={dialog} onOpen={() => onNavigate('nodes', ask)} />
}
