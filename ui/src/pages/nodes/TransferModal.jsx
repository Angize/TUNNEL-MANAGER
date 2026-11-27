import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import Field from '../../components/Field.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import useProxies from '../../lib/useProxies.js'
import SshAuth from './SshAuth.jsx'
import { isNodeNameValid } from './nodeName.js'
import NodeIpField from './NodeIpField.jsx'
import { isIpv4 } from '../../lib/cdn.js'
import { T } from '../../i18n/fa.js'
import { formatNumber, latinDigits } from '../../lib/num.js'
import { destinationInventory, startPreparation, runTransfer } from './transferService.js'
import TransferDetails from './TransferDetails.jsx'
import useInstallJob from './useInstallJob.js'
import InstallProgress, { InstallReport } from './InstallProgress.jsx'
import './transfer.css'

const steps = ['مقصد', 'آماده‌سازی', 'تونل‌ها', 'انتقال']
const empty = { name: '', host: '', port: '22', user: 'root', agentPort: '8099', mode: 'pass', pass: '', key: '' }

function StepRail({ step }) {
  return <ol className="nt-steps" aria-label="مراحل انتقال">{steps.map((name,i) =>
    <li key={name} className={i === step ? 'here' : i < step ? 'done' : ''} aria-current={i === step ? 'step' : undefined}>
      <span>{i < step ? <Icon name="check" /> : formatNumber(i + 1)}</span>{name}
    </li>)}</ol>
}

function Route({ source, dest }) {
  return <div className="nt-route">
    <div><small>مبدأ</small><strong><bdi>{source}</bdi></strong></div>
    <span aria-hidden="true"><Icon name="back" /></span>
    <div><small>مقصد</small><strong><bdi>{dest}</bdi></strong></div>
  </div>
}

function Item({ icon, label, detail, value, tone }) {
  return <div className="nt-item"><i><Icon name={icon} /></i><div className="nt-grow"><b>{label}</b>{detail && <small>{detail}</small>}</div>
    <span className={'nt-state ' + (tone || '')}>{value}</span></div>
}

function formErrors(form, source) {
  const errors = {}
  if (!isNodeNameValid(form.name.trim())) errors.name = 'نام نود را با حروف لاتین، عدد، فاصله، نقطه یا خط بنویس (حداکثر 40 نویسه).'
  if (!isIpv4(form.host.trim())) errors.host = T('node_ip_invalid')
  else if (form.host.trim() === source.host) errors.host = 'مقصد و مبدأ یکی هستند.'
  if (!form.user.trim()) errors.user = 'نام کاربر اتصال را وارد کن.'
  for (const key of ['port', 'agentPort']) {
    const v = latinDigits(form[key]).trim()
    if (!/^\d+$/.test(v) || +v < 1 || +v > 65535) errors[key] = 'یک پورت بین 1 و 65535 وارد کن.'
  }
  if (!(form.mode === 'key' ? form.key.trim() : form.pass)) errors.auth = form.mode === 'key' ? 'کلید خصوصی را وارد کن.' : 'گذرواژه را وارد کن.'
  return errors
}

export default function TransferModal({ node, nodes, filtered, onClose }) {
  const [form, setForm] = useState(empty)
  const [step, setStep] = useState(0)
  const [errors, setErrors] = useState({})
  const [inventory, setInventory] = useState(null)
  const [busy, setBusy] = useState(false)
  const [fault, setFault] = useState('')
  const [selected, setSelected] = useState([])
  const [clean, setClean] = useState(false)
  const [results, setResults] = useState(null)
  const { state: progress, start, reset } = useInstallJob({
    onFinished(success, banner, transfer) {
      if (success) setInventory(destinationInventory(transfer))
      setBusy(false)
    }
  })
  const failed = !!fault || (progress?.finished && !progress.success)
  const proxies = useProxies()
  const [chosenProxy, setChosenProxy] = useState(null)
  const known = nodes.find(n => n.host.toLowerCase() === form.host.trim().toLowerCase())
  const proxy = chosenProxy || { on: !!known?.proxy_on, id: known?.proxy_id || '' }
  const title = useRef(null)
  useEffect(() => { if (step) title.current?.focus() }, [step])
  const write = (key, value) => {
    setForm(f => ({ ...f, [key]: value }))
    setErrors(e => ({ ...e, [key === 'pass' || key === 'key' || key === 'mode' ? 'auth' : key]: '' }))
  }
  async function prepare() {
    if (progress?.resume) {
      setBusy(true)
      start(progress.job, progress)
      return
    }
    const issues = formErrors(form, node)
    if (chosenProxy?.on && !proxies.some(p => p.id === chosenProxy.id)) issues.proxy = 'یک پروکسی از فهرست انتخاب کن.'
    setErrors(issues)
    if (Object.keys(issues).length) {
      setStep(0)
      requestAnimationFrame(() => document.querySelector('.nt-modal [aria-invalid=true],.nt-modal .nt-auth-error ' +
        (form.mode === 'key' ? 'textarea' : 'input') + ',.nt-modal .nt-proxy-error [role=switch]')?.focus())
      return
    }
    setStep(1); setFault(''); setBusy(true); setInventory(null)
    reset()
    try { start(await startPreparation(node, form, chosenProxy ? proxyBody(chosenProxy) : {})) }
    catch (err) { setFault(err.message); setBusy(false) }
  }
  const tunnels = inventory?.sourceTunnels || []
  const selectedIds = new Set(selected)
  const picked = tunnels.filter(t => selectedIds.has(t.id))
  const eligible = tunnels.filter(t => !t.blocked)
  async function transfer() {
    setFault(''); setBusy(true)
    setResults(rows => rows || Object.fromEntries(picked.map(t => [t.id,{ status: 'در صف' }])))
    try {
      await runTransfer(progress.job, picked, clean, changes => setResults(r => ({ ...r, ...changes })))
    } catch (err) {
      setFault(err.message)
      setResults(rows => Object.fromEntries(Object.entries(rows).map(([id, row]) =>
        [id, row.final ? row : { status: 'نتیجه نامشخص', tone: 'wait' }])))
    } finally { setBusy(false) }
  }
  const back = () => {
    setFault('')
    if (step === 1) { reset(); setInventory(null); setSelected([]); setClean(false) }
    if (step) setStep(step - 1); else onClose()
  }
  const next = () => {
    if (step === 0 || (step === 1 && failed)) return prepare()
    if (step < 3) return setStep(step + 1)
    if (results && !fault) return onClose()
    return transfer()
  }
  const primary = busy ? step === 1 ? 'آماده‌سازی…' : 'در حال انتقال…'
    : step === 0 ? 'آماده‌سازی مقصد' : step === 1 ? failed ? 'تلاش دوباره' : 'انتخاب تونل‌ها'
    : step === 2 ? 'مرور انتقال' : results ? fault ? 'پیگیری نتیجه' : 'پایان' : 'شروع انتقال'
  const heading = ['مشخصات نود مقصد', 'آماده‌سازی نود مقصد', 'کدام تونل‌ها منتقل شوند؟', results ? busy ? 'انتقال در حال انجام است' : 'نتیجهٔ انتقال' : 'مرور و تأیید انتقال'][step]
  const field = (key, label, props = {}) => <Field label={label} error={errors[key]}>
    <input dir="ltr" value={form[key]} onChange={e => write(key,e.target.value)} {...props} /></Field>
  const footer = <>
    <button type="button" className="primary" aria-busy={busy} disabled={busy || (step === 2 && !picked.length)} onClick={next}>
      {busy && <span className="bspin sm" />}{primary}</button>
    {!results && <button type="button" className="ghost" disabled={busy} onClick={back}>{step ? 'بازگشت' : 'انصراف'}</button>}
  </>
  return <Modal icon="nodeTransfer" title="انتقال نود" subtitle={<>از نود <bdi>{node.name}</bdi></>} cls="nt-modal" onClose={() => { if (!busy) onClose() }} footer={footer}>
    <StepRail step={step} />
    {step >= 2 && <Route source={node.name} dest={form.name} />}
    <div className="nt-heading"><h4 tabIndex={-1} ref={title}>{heading}</h4>{step === 2 && <span>{formatNumber(picked.length)} از {formatNumber(tunnels.length)} انتخاب شده</span>}</div>
    {step === 0 && <>
      <div className="grid2">{field('name','نام نود مقصد',{placeholder:'IR-02'})}
        <NodeIpField placeholder="192.0.2.22" value={form.host} error={errors.host} onChange={host => write('host',host)} /></div>
      <div className="grid2">{field('user','کاربر اتصال')}{field('port','پورت اتصال',{inputMode:'numeric'})}</div>
      <div className="grid2">{field('agentPort','پورت ایجنت',{inputMode:'numeric'})}</div>
      <div className={errors.auth ? 'nt-auth-error' : ''}><SshAuth mode={form.mode} onMode={v => write('mode',v)} pass={form.pass} onPass={v => write('pass',v)} sshKey={form.key} onKey={v => write('key',v)} />
      {errors.auth && <small className="nt-error" role="alert">{errors.auth}</small>}</div>
      <div className={errors.proxy ? 'nt-proxy-error' : undefined}>
        <ProxyFields proxies={proxies} value={proxy} onChange={value => { setChosenProxy(value); setErrors(e => ({ ...e, proxy: '' })) }} />
        {errors.proxy && <small className="nt-error" role="alert">{errors.proxy}</small>}
        {filtered && !known && !chosenProxy && <small>برای مقصد ثبت‌شده، تنظیم اتصال فعلی آن استفاده می‌شود.</small>}
      </div>
      <p className="nt-note"><Icon name="info" />اگر ایجنت یا هسته نصب نباشد، طبق تنظیمات نصب پنل آماده می‌شود.</p>
    </>}
    {step === 1 && <>
      {progress ? <InstallProgress state={progress} /> : <InstallReport tone={fault ? 'err' : 'run'} banner={fault || T('inst_ssh')} />}
      {inventory && <div className="nt-box">
        {['agent','core'].map((key,i) => <Item key={key} icon={i ? 'cpu' : 'agent'} label={i ? 'هسته' : 'ایجنت'} tone="ok" {...inventory[key]} />)}
        <Item icon="link" label="تونل‌های موجود در مقصد" value={formatNumber(inventory.existing.length) + ' تونل'} detail={inventory.existing.map(t => t.name).join('، ')} />
      </div>}
    </>}
    {step === 2 && <>
      <div className="nt-box">
        {!!eligible.length && <label className="nt-choice nt-all"><input type="checkbox" checked={eligible.length === picked.length}
          ref={el => { if (el) el.indeterminate = picked.length > 0 && picked.length < eligible.length }}
          onChange={e => setSelected(e.target.checked ? eligible.map(t => t.id) : [])} />انتخاب همه</label>}
        {tunnels.map(t => <div key={t.id} className="nt-entry"><div className="nt-pickrow"><label className={'nt-choice' + (selectedIds.has(t.id) ? ' chosen' : '')}>
          <input type="checkbox" disabled={!!t.blocked} checked={selectedIds.has(t.id)} onChange={e => setSelected(ids => e.target.checked ? [...ids,t.id] : ids.filter(id => id !== t.id))} />
          <div className="nt-grow"><b><bdi>{t.name}</bdi></b><small>{t.blocked || <>نود مقابل <bdi>{t.peer}</bdi></>}</small></div><span className="nt-tag"><bdi>{t.kind}</bdi></span></label><TransferDetails tunnel={t} /></div></div>)}
        {!tunnels.length && <p className="nt-note">تونلی برای انتقال روی مبدأ وجود ندارد.</p>}
      </div>
      <label className={'nt-choice nt-clean' + (clean ? ' armed' : '')}><input type="checkbox" checked={clean} onChange={e => setClean(e.target.checked)} />
        <div><b>پاک‌کردن تونل‌های منتقل‌شده از مبدأ</b><small>هر تونل فقط بعد از انتقال موفق خودش پاک می‌شود.</small></div></label>
    </>}
    {step === 3 && <><div className="nt-box" aria-live="polite">{picked.map(t => {
      const row = results?.[t.id]
      return <Item key={t.id} icon={row?.tone === 'ok' ? 'okc' : row?.tone === 'bad' ? 'warn' : 'link'} label={<bdi>{t.name}</bdi>}
        detail={row?.detail || <>نود مقابل <bdi>{t.peer}</bdi></>} value={row?.status || t.kind} tone={row?.tone} />
    })}</div>
    {!results && <p className="nt-note">پس از انتقال، نودِ همین تونل‌ها در پنل به <bdi>{form.name}</bdi> تغییر می‌کند.</p>}
    <p className={'nt-policy' + (clean ? ' armed' : '')}><Icon name={clean ? 'trash' : 'shield'} />{clean ? 'نسخهٔ قبلی هر تونل موفق از مبدأ پاک می‌شود.' : 'نسخهٔ قبلی تونل‌ها روی مبدأ می‌ماند.'}</p>
    {fault && <p className="nt-error" role="alert">{fault}</p>}</>}
  </Modal>
}
