import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { TUNNEL_TYPES } from '../../lib/subnet.js'
import { latinDigits } from '../../lib/num.js'

const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const modes = { github: 'دریافت از گیت‌هاب', push: 'ارسال از پنل', panel: 'دریافت از پنل' }
function componentStatus(state, mode) {
  const installed = state === 'installed'
  return { value: installed ? 'نصب شد' : 'از قبل نصب بود', detail: installed && modes[mode] ? 'روش نصب پنل: ' + modes[mode] : '' }
}

async function readJob(job, after) {
  let last
  for (let i = 0; i < 4; i++) {
    try { return await apiGet('install-status?job=' + encodeURIComponent(job) + '&after=' + after) }
    catch (err) { last = err; if (err.status >= 400 && err.status < 500) throw err; if (i < 3) await delay(600 * (i + 1)) }
  }
  throw Error(readError(last))
}

export async function startPreparation(node, form, proxy) {
  const r = await apiPost('transfer-prepare', {
    source: node.id, name: form.name.trim(), ssh_host: form.host.trim(), ...proxy,
    ssh_user: form.user.trim(), ssh_port: latinDigits(form.port), agent_port: latinDigits(form.agentPort),
    ssh_pass: form.mode === 'pass' ? form.pass : '', ssh_key: form.mode === 'key' ? form.key : ''
  })
  if (!r.ok || !r.d.ok) throw Error(postError(r))
  return r.d.job
}

export function destinationInventory(inventory) {
  return {
    ...inventory,
    agent: componentStatus(inventory.agent, inventory.agentMode),
    core: componentStatus(inventory.core, inventory.coreMode),
    sourceTunnels: inventory.sourceTunnels.map(t => ({ ...t, kind: t.kind === 'core' ? 'هسته'
      : TUNNEL_TYPES.find(type => type.v === t.kind)?.label || t.kind }))
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
  let after = 0
  for (;;) {
    const j = await readJob(job, after)
    const changed = {}
    for (const [id,row] of Object.entries(j.results || {})) {
      const done = row.state === 'done'
      changed[id] = done ? { status: 'منتقل شد', final: true, tone: row.detail === 'lost' || row.detail === 'changed' ? 'wait' : 'ok', detail: outcomes[row.detail] }
        : row.state === 'unknown' ? { status: 'نیاز به بررسی', final: true, tone: 'wait', detail: translateError(row.detail) }
        : row.state === 'run' ? { status: 'در حال انتقال…', tone: 'wait' }
        : { status: 'منتقل نشد', final: true, tone: 'bad', detail: translateError(row.detail) }
    }
    if (Object.keys(changed).length) publish(changed)
    after = j.after
    if (j.transfer_done) return
    await delay(600)
  }
}
