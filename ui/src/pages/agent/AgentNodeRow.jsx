import Icon from '../../components/Icon.jsx'
import Reveal from '../../components/Reveal.jsx'
import PushBar, { pushTone } from './PushBar.jsx'
import { coreVersionName, versionIsNewer } from './versions.js'
import { T } from '../../i18n/fa.js'

function VersionPill({ tone, version, title }) {
  return (
    <span className={'vp ' + tone} title={title}>
      {version}
    </span>
  )
}

function agentPill(node, agentMeta, fromGit) {
  const label = T('ag_lbl_agent')
  const info = node.info || {}
  const hasUpdate = !!(agentMeta && !agentMeta.none && info.sha256 !== agentMeta.sha256)
  const highlight = hasUpdate && node.online
  if (!node.online) return { tone: 'offl', title: label + ': ' + T('offline'), disabled: true, highlight }
  if (agentMeta && agentMeta.none && fromGit) {
    return { tone: 'na', title: label + ': ' + T('ag_from_git'), disabled: false, highlight }
  }
  if (!agentMeta || agentMeta.none) return { tone: 'offl', title: label, disabled: true, highlight }
  if (hasUpdate) return { tone: 'up', title: label + ': ' + T('ag_up_avail'), disabled: false, highlight }
  return { tone: 'ok', title: label + ': ' + T('ag_uptodate'), disabled: true, highlight }
}

function customPill(label, info, installed, customSha) {
  if (installed && String(info.core_sha) === String(customSha)) {
    return { tone: 'ok', title: label + ': ' + T('ag_uptodate'), disabled: true, highlight: false }
  }
  return {
    tone: installed ? 'ok' : 'na',
    title: label + ': ' + T('ag_ver_pick').replace('{v}', coreVersionName('custom')),
    disabled: false,
    highlight: false,
  }
}

function corePill(node, staged, wanted, customSha) {
  const label = T('ag_lbl_core')
  const info = node.info || {}
  const installed = !!(info.core_sha && String(info.core_sha).length)
  if (!node.online) return { tone: 'offl', title: label + ': ' + T('offline'), disabled: true, highlight: false }
  if (wanted === 'custom') return customPill(label, info, installed, customSha)
  const arch = info.arch || 'amd64'
  const stagedSha = (staged && staged.sha && staged.sha[arch]) || ''
  const stagedVersion = String((staged && staged.version) || '')
  const wantDiff = !!(wanted && installed && String(info.core_ver || '') !== wanted)
  const stagedDiff = !!(
    staged &&
    (!installed ||
      (stagedSha
        ? String(info.core_sha) !== String(stagedSha).slice(0, 12)
        : !!stagedVersion && String(info.core_ver || '') !== stagedVersion))
  )
  const hasUpdate = stagedDiff && !versionIsNewer(info.core_ver, stagedVersion)
  const highlight = hasUpdate

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

export default function AgentNodeRow({
  node,
  agentMeta,
  agentFromGit,
  staged,
  wanted,
  customSha,
  status,
  onPushAgent,
  onPushCore,
}) {
  const info = node.info || {}
  const installed = !!(info.core_sha && String(info.core_sha).length)
  const agent = agentPill(node, agentMeta, agentFromGit)
  const core = corePill(node, staged, wanted, customSha)

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
          tone={agent.tone}
          version={info.version || '—'}
          title={agent.title}
        />
        <VersionPill
          tone={core.tone}
          version={installed ? coreVersionName(String(info.core_ver || '?')) : '—'}
          title={core.title}
        />
      </div>

      <Reveal show={!!status}>
        {status ? (
          <div className={'msg agres' + (pushTone(status) ? ' ' + pushTone(status) : '')}>
            <PushBar status={status} />
          </div>
        ) : null}
      </Reveal>

      <div className="nxa">
        <button
          className={'ib' + (agent.highlight ? ' up' : '')}
          disabled={agent.disabled}
          title={T('ag_send') + ' ' + T('ag_lbl_agent')}
          onClick={() => onPushAgent(node.id)}
        >
          <Icon name="server" />
          <span>{T('ag_lbl_agent')}</span>
        </button>
        <button
          className={'ib' + (core.highlight ? ' up' : '')}
          disabled={core.disabled}
          title={T('ag_send') + ' ' + T('ag_lbl_core')}
          onClick={() => onPushCore(node.id)}
        >
          <Icon name="cpu" />
          <span>{T('ag_lbl_core')}</span>
        </button>
      </div>
    </div>
  )
}
