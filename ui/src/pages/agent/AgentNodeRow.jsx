import Icon from '../../components/Icon.jsx'
import PushBar, { pushTone } from './PushBar.jsx'
import { coreVersionName, versionIsNewer } from './versions.js'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

function VersionPill({ icon, tone, version, title }) {
  return (
    <span className={'vp ' + tone} title={title}>
      <Icon name={icon} />
      {version}
    </span>
  )
}

function agentPill(node, agentMeta) {
  const label = T('ag_lbl_agent')
  const info = node.info || {}
  const hasUpdate = !!(agentMeta && !agentMeta.none && info.sha256 !== agentMeta.sha256)
  const highlight = hasUpdate && node.online
  if (!node.online) return { tone: 'offl', title: label + ': ' + T('offline'), disabled: true, highlight }
  if (!agentMeta || agentMeta.none) return { tone: 'offl', title: label, disabled: true, highlight }
  if (hasUpdate) return { tone: 'up', title: label + ': ' + T('ag_up_avail'), disabled: false, highlight }
  return { tone: 'ok', title: label + ': ' + T('ag_uptodate'), disabled: true, highlight }
}

function corePill(node, staged, wanted) {
  const label = T('ag_lbl_core')
  const info = node.info || {}
  const installed = !!(info.core_sha && String(info.core_sha).length)
  const arch = info.arch || 'amd64'
  const stagedSha = (staged && staged.sha && staged.sha[arch]) || ''
  const stagedVersion = String((staged && staged.version) || '')
  const wantDiff = !!(wanted && wanted !== 'custom' && installed && String(info.core_ver || '') !== wanted)
  const stagedDiff = !!(
    staged &&
    (!installed ||
      (stagedSha
        ? String(info.core_sha) !== String(stagedSha).slice(0, 12)
        : !!stagedVersion && String(info.core_ver || '') !== stagedVersion))
  )
  const hasUpdate = stagedDiff && !versionIsNewer(info.core_ver, stagedVersion)
  const highlight = hasUpdate && node.online

  if (!node.online) return { tone: 'offl', title: label + ': ' + T('offline'), disabled: true, highlight }
  if (!installed) {
    return {
      tone: 'na',
      title: label + ': ' + T('ag_not_installed'),
      disabled: !(staged || wanted),
      highlight,
    }
  }
  if (hasUpdate) return { tone: 'up', title: label + ': ' + T('ag_up_avail'), disabled: false, highlight }
  if (wantDiff || stagedDiff) {
    return {
      tone: 'ok',
      title: label + ': ' + T('ag_ver_pick').replace('{v}', coreVersionName(wanted || stagedVersion)),
      disabled: false,
      highlight,
    }
  }
  return { tone: 'ok', title: label + ': ' + T('ag_uptodate'), disabled: true, highlight }
}

export default function AgentNodeRow({ node, agentMeta, staged, wanted, status, onPushAgent, onPushCore }) {
  const info = node.info || {}
  const installed = !!(info.core_sha && String(info.core_sha).length)
  const agent = agentPill(node, agentMeta)
  const core = corePill(node, staged, wanted)

  return (
    <div className="nx">
      <div className="nxh">
        <span className={'ndot ' + (node.online ? 'on' : 'off')} />
        <span className="nmwrap">
          <span className="nm">{node.name}</span>
          <span className="nxhost">{node.host || ''}</span>
        </span>
      </div>

      <div className="nxv">
        <VersionPill
          icon="server"
          tone={agent.tone}
          version={info.version ? 'v' + num(info.version) : '—'}
          title={agent.title}
        />
        <VersionPill
          icon="cpu"
          tone={core.tone}
          version={installed ? coreVersionName(String(info.core_ver || '?')) : '—'}
          title={core.title}
        />
      </div>

      <div className={'msg agres' + (status ? ' ' + pushTone(status) : '')}>
        {status ? <PushBar status={status} /> : null}
      </div>

      <div className="nxa">
        <button
          className={'ib' + (agent.highlight ? ' up' : '')}
          disabled={agent.disabled}
          title={T('ag_send') + ' ' + T('ag_lbl_agent')}
          onClick={() => onPushAgent(node.id)}
        >
          <Icon name="server" />
        </button>
        <button
          className={'ib' + (core.highlight ? ' up' : '')}
          disabled={core.disabled}
          title={T('ag_send') + ' ' + T('ag_lbl_core')}
          onClick={() => onPushCore(node.id)}
        >
          <Icon name="cpu" />
        </button>
      </div>
    </div>
  )
}
