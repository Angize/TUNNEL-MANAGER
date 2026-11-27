import { apiGet, apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { TUNNEL_TYPES } from '../../lib/subnet.js'
import { latinDigits } from '../../lib/num.js'

const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const modes = { github: 'دریافت از گیت‌هاب', push: 'ارسال از پنل', panel: 'دریافت از پنل' }
const states = {
  checking: ['در حال بررسی…', ''], installing: ['در حال نصب…', 'wait'],
  installed: ['نصب شد', 'ok'], present: ['نصب است', 'ok']
}

function componentStatus(state, mode) {
  const [status, tone] = states[state] || states.checking
  return { status, tone, detail: modes[mode] ? 'روش نصب پنل: ' + modes[mode] : '' }
}

async function readJob(job) {
  let last
  for (let i = 0; i < 4; i++) {
    try { return await apiGet('install-status?job=' + encodeURIComponent(job)) }
    catch (err) { last = err; if (err.status === 400) throw err; await delay(600 * (i + 1)) }
  }
  throw last
}

export async function prepareDestination(node, form, publish) {
  const r = await apiPost('transfer-prepare', {
    source: node.id, name: form.name.trim(), ssh_host: form.host.trim(),
    ssh_user: form.user.trim(), ssh_port: latinDigits(form.port), agent_port: latinDigits(form.agentPort),
    ssh_pass: form.mode === 'pass' ? form.pass : '', ssh_key: form.mode === 'key' ? form.key : ''
  })
  if (!r.ok || !r.d.ok) throw Error(postError(r))
  const job = r.d.job
  for (;;) {
    const j = await readJob(job)
    const inventory = j.transfer || {}
    const sourceTunnels = inventory.sourceTunnels?.map(t => ({ ...t, kind: t.kind === 'core' ? 'هسته'
      : TUNNEL_TYPES.find(type => type.v === t.kind)?.label || t.kind }))
    publish({ ...inventory, sourceTunnels, job, agent: componentStatus(inventory.agent, inventory.agentMode),
      core: componentStatus(inventory.core, inventory.coreMode) })
    if (j.done) {
      if (!j.success) {
        const step = j.steps.find(s => s.state === 'err')
        throw Error(translateError([step?.detail || j.banner, step?.log].filter(Boolean).join(' — ')))
      }
      return
    }
    await delay(550)
  }
}

const outcomes = {
  done: 'نود در پنل به‌روز شد و نسخهٔ مبدأ پاک شد.',
  kept: 'نود در پنل به‌روز شد. نسخهٔ مبدأ حفظ شد.',
  changed: 'تونل روی مبدأ تغییر کرده بود. نسخهٔ تغییرکرده حفظ شد.',
  lost: 'نود در پنل به‌روز شد. پاک‌سازی مبدأ انجام نشد؛ آن را دستی بررسی کن.'
}

export async function runTransfer(job, picked, clean, publish) {
  const r = await apiPost('transfer-run', { job, links: picked.map(t => t.id), clean })
  if (!r.ok || !r.d.ok) throw Error(postError(r))
  for (;;) {
    const j = await readJob(job)
    for (const [id,row] of Object.entries(j.results || {})) {
      const done = row.state === 'done'
      publish(id, done ? { status: 'منتقل شد', tone: row.detail === 'lost' || row.detail === 'changed' ? 'wait' : 'ok', detail: outcomes[row.detail] }
        : row.state === 'run' ? { status: 'در حال انتقال…', tone: 'wait' }
        : {status: 'منتقل نشد', tone: 'bad', detail: translateError(row.detail)})
    }
    if (j.transfer_done) return
    await delay(600)
  }
}
