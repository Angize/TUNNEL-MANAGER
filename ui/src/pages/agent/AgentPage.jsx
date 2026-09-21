import { useCallback, useEffect, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import { AgentRowsSkeleton } from '../../components/Skeleton.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import Select from '../../components/Select.jsx'
import { Check } from '../../components/Marks.jsx'
import AgentNodeRow from './AgentNodeRow.jsx'
import DeliverySegment from './DeliverySegment.jsx'
import PushFab from './PushFab.jsx'
import usePushJob from './usePushJob.js'
import { coreVersionName } from './versions.js'
import { T, TF } from '../../i18n/fa.js'
import { useSummary } from '../../state/SummaryContext.jsx'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import { MAX_POLL_FAILURES, setPageRefresh } from '../../lib/poll.js'
import './agent.css'

const STAGE_POLL_MS = 400

function Meta({ children }) {
  return <div className="opmeta">{children}</div>
}

function Message({ value, onCancel }) {
  return (
    <div className={value ? 'msg ' + value.cls : 'msg'}>
      {value ? (
        value.progress != null ? (
          <>
            <div className="pushbar">
              <i style={{ width: value.progress + '%' }} />
            </div>
            <div className="plbl">
              <span>{T('cor_downloading')}</span>
              <b>{value.progress}%</b>
            </div>
            <button type="button" className="ghost" style={{ marginTop: 8 }} onClick={onCancel}>
              <Icon name="xc" />
              {T('cor_dl_cancel')}
            </button>
          </>
        ) : (
          <>
            {value.text}
            {value.check ? <Check /> : null}
          </>
        )
      ) : null}
    </div>
  )
}

export default function AgentPage({ headless }) {
  const { counts } = useSummary()
  const [agentMeta, setAgentMeta] = useState(null)
  const [versions, setVersions] = useState(null)
  const [staged, setStaged] = useState(null)
  const [coreReady, setCoreReady] = useState({ ready: false, missing: [] })
  const [wanted, setWanted] = useState('')
  const [delivery, setDelivery] = useState({ agent: 'push', core: 'push' })
  const [nodes, setNodes] = useState(null)
  const [query, setQuery] = useState('')
  const [proxies, setProxies] = useState([])
  const [dlProxy, setDlProxy] = useState(null)
  const [dlError, setDlError] = useState('')
  const [agentMsg, setAgentMsg] = useState(null)
  const [gitMsg, setGitMsg] = useState(null)
  const [coreMsg, setCoreMsg] = useState(null)
  const [proxyMsg, setProxyMsg] = useState(null)
  const [gitBusy, setGitBusy] = useState(false)
  const agentFile = useRef(null)
  const coreFile = useRef(null)
  const queryRef = useRef(query)
  const mounted = useRef(true)
  const staging = useRef(false)
  const adoptStage = useRef(null)

  queryRef.current = query

  const loadAgentInfo = useCallback(async () => {
    let info
    try {
      info = await apiGet('agent-info')
    } catch {
      return
    }
    setAgentMeta(info)
    setDelivery((prev) => ({ ...prev, agent: info.delivery }))
  }, [])

  const loadCoreVersions = useCallback(async () => {
    let r
    try {
      r = await apiGet('core-versions')
    } catch {
      return
    }
    setVersions(r.versions)
    setStaged(r.staged)
    setCoreReady({ ready: !!r.ready, missing: r.missing || [] })
    setDelivery((prev) => ({ ...prev, core: r.delivery }))
    setWanted((prev) => {
      if (prev) return prev
      if (r.staged && r.staged.version) return r.staged.version
      const release = r.versions.find((v) => !v.custom)
      return release ? release.id : ''
    })
  }, [])

  const loadNodes = useCallback(async () => {
    const asked = queryRef.current
    let r
    try {
      r = await apiGet('nodes?q=' + encodeURIComponent(asked))
    } catch {
      return
    }
    if (asked !== queryRef.current) return
    setNodes(r.nodes)
  }, [])

  const refreshAll = useCallback(async () => {
    await Promise.all([loadAgentInfo(), loadCoreVersions(), loadNodes()])
  }, [loadAgentInfo, loadCoreVersions, loadNodes])

  const push = usePushJob({ onSettled: refreshAll })

  const adoptPush = push.adopt

  const agentUnknown = agentMeta === null
  const coreUnknown = versions === null

  useEffect(() => {
    refreshAll()
    adoptPush()
  }, [refreshAll, adoptPush])

  useEffect(() => {
    mounted.current = true
    adoptStage.current()
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(
    () =>
      setPageRefresh(() =>
        Promise.all([loadNodes(), agentUnknown && loadAgentInfo(), coreUnknown && loadCoreVersions()])
      ),
    [loadNodes, loadAgentInfo, loadCoreVersions, agentUnknown, coreUnknown]
  )

  useEffect(() => {
    loadNodes()
  }, [query, loadNodes])

  const loadDlProxy = useCallback(async () => {
    setDlError('')
    try {
      const [px, s] = await Promise.all([apiGet('proxies'), apiGet('settings')])
      setProxies(px.proxies)
      setDlProxy({ on: !!s.dl_proxy_on, id: String(s.dl_proxy_id || '') })
    } catch (e) {
      setDlError(readError(e))
    }
  }, [])

  useEffect(() => {
    loadDlProxy()
  }, [loadDlProxy])

  const changeDelivery = async (kind, value) => {
    if (delivery[kind] === value) return
    const was = delivery[kind]
    setDelivery((prev) => ({ ...prev, [kind]: value }))
    const r = await apiPost('settings-set', { [kind + '_delivery']: value })
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      if (kind === 'core') loadCoreVersions()
      return
    }
    setDelivery((prev) => ({ ...prev, [kind]: was }))
    toast(postError(r), 'err')
  }

  const fetchAgentFromGit = async () => {
    setGitBusy(true)
    setGitMsg({ cls: '', text: T('ag_fetching_git') })
    const r = await apiPost('agent-fetch-git', {})
    setGitBusy(false)
    if (!(r.ok && r.d.ok)) {
      setGitMsg(null)
      alertBox(postError(r))
      return
    }
    setGitMsg({
      cls: 'ok',
      check: true,
      text: T('ag_fetched_pre') + r.d.version + ' · ' + r.d.sha256 + T('ag_fetched_post'),
    })
    await refreshAll()
  }

  const uploadAgentFile = (input) => {
    const file = input.files && input.files[0]
    if (!file) return
    input.value = ''
    const reader = new FileReader()
    reader.onload = async () => {
      const code = String(reader.result || '')
      if (!code.trim()) {
        alertBox(T('ag_pick_file_first'))
        return
      }
      setAgentMsg({ cls: '', text: T('ag_checking_saving') })
      const r = await apiPost('agent-upload', { code })
      if (r.ok && r.d.ok) {
        setAgentMsg({ cls: 'ok', text: T('ag_saved_pre') + r.d.version + ' · ' + r.d.sha256 })
        await refreshAll()
        return
      }
      setAgentMsg(null)
      alertBox(postError(r))
    }
    reader.readAsText(file)
  }

  const onlineIds = async () => {
    try {
      const r = await apiGet('node-names')
      return r.nodes.filter((n) => n.online).map((n) => n.id)
    } catch (e) {
      toast(readError(e), 'err')
      return null
    }
  }

  const pushAgent = async (target) => {
    if (agentUnknown) {
      toast(T('net_read'), 'err')
      return
    }
    if (agentMeta.none && delivery.agent !== 'github') {
      toast(T('ag_pick_first'), 'err')
      return
    }
    let ids
    if (target === 'all') {
      ids = await onlineIds()
      if (!ids) return
      if (!ids.length) {
        toast(T('ag_no_online'), 'err')
        return
      }
      const ok = await confirmBox(
        T('ag_confirm_all') + ids.length + T('ag_confirm_all2'),
        T('yes_all')
      )
      if (!ok) return
    } else {
      ids = [target]
    }
    await push.start('update-agent', { ids }, ids)
  }

  const checkCore = async () => {
    setCoreMsg({ cls: '', text: T('cor_checking') })
    const res = await apiPost('core-check', {})
    const d = res.d
    if (!(res.ok && d.ok)) {
      setCoreMsg(null)
      alertBox(postError(res, 'err_github'))
      return
    }
    await loadCoreVersions()
    const button = T(delivery.core === 'github' ? 'cor_pick_git' : 'ag_fetch_git')
    setCoreMsg({
      cls: 'ok',
      text: !d.count
        ? T('cor_check_none')
        : d.latest === d.staged
          ? T('cor_check_same')
          : d.first_check
            ? T('cor_check_first').replace('{n}', d.count)
            : d.newer
              ? TF('cor_check_new', { b: button })
              : TF('cor_check_avail', { v: d.latest, b: button }),
    })
  }

  const stageDone = async (d) => {
    const missing = d.missing || []
    setCoreMsg({
      cls: missing.length ? '' : 'ok',
      check: !missing.length,
      text:
        T('cor_staged_pre') +
        d.version +
        T(d.meta_only ? 'cor_picked_post' : 'cor_staged_post') +
        ((d.arches || []).length ? ' (' + d.arches.join(', ') + ')' : '') +
        (missing.length ? T('cor_arch_missing').replace('{a}', missing.join('، ')) : ''),
    })
    await loadCoreVersions()
  }

  const watchStage = async (job) => {
    setCoreMsg({ cls: '', progress: 0 })
    let failures = 0
    for (;;) {
      let r
      try {
        r = await apiGet('core-stage-status')
        failures = 0
      } catch {
        failures += 1
      }
      if (!mounted.current) return
      if (failures >= MAX_POLL_FAILURES) {
        setCoreMsg({ cls: '', text: T('cor_dl_lost') })
        return
      }
      if (r && r.job !== job) {
        setCoreMsg(null)
        alertBox(T('cor_dl_gone'))
        return
      }
      if (r && r.done) {
        if (r.err) {
          setCoreMsg(null)
          alertBox(translateError(r.err))
        } else {
          await stageDone(r)
        }
        return
      }
      if (r) setCoreMsg({ cls: '', progress: Math.max(0, Math.min(100, num(r.pct))) })
      await new Promise((done) => setTimeout(done, STAGE_POLL_MS))
    }
  }

  const attachRunning = async () => {
    let status = null
    try {
      status = await apiGet('core-stage-status')
    } catch {
      return false
    }
    if (!mounted.current || !status || status.done || !status.job) return false
    await watchStage(status.job)
    return true
  }

  adoptStage.current = async () => {
    if (staging.current) return
    staging.current = true
    try {
      await attachRunning()
    } finally {
      staging.current = false
    }
  }

  const stageCore = async () => {
    if (staging.current) return
    staging.current = true
    try {
      if (await attachRunning()) return
      if (!mounted.current) return
      const version = wanted || 'latest'
      setCoreMsg({ cls: '', text: T(delivery.core === 'github' ? 'cor_picking' : 'cor_downloading') })
      const res = await apiPost('core-stage', { version })
      if (!mounted.current) return
      if (!(res.ok && res.d.ok)) {
        setCoreMsg(null)
        alertBox(postError(res, 'err_github'))
        return
      }
      if (res.d.done) {
        await stageDone(res.d)
        return
      }
      await watchStage(res.d.job)
    } finally {
      staging.current = false
    }
  }

  const cancelStage = async () => {
    const r = await apiPost('core-stage-cancel', {})
    if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
  }

  const uploadCoreBinary = (input) => {
    const file = input.files && input.files[0]
    if (!file) return
    input.value = ''
    setCoreMsg({ cls: '', text: T('cor_reading_upload') })
    const reader = new FileReader()
    reader.onerror = () => {
      setCoreMsg(null)
      alertBox(T('cor_read_fail'))
    }
    reader.onload = async () => {
      const raw = String(reader.result || '')
      const comma = raw.indexOf(',')
      const res = await apiPost('core-upload', {
        data: comma >= 0 ? raw.slice(comma + 1) : raw,
        name: file.name,
      })
      if (res.ok && res.d.ok) {
        setCoreMsg({
          cls: 'ok',
          check: true,
          text:
            T('cor_bin_saved_pre') +
            file.name +
            ' · ' +
            Math.round(res.d.size / 1024) +
            'KB · ' +
            res.d.sha256 +
            T('cor_bin_saved_post'),
        })
        setWanted('custom')
        await loadCoreVersions()
        return
      }
      setCoreMsg(null)
      alertBox(postError(res))
    }
    reader.readAsDataURL(file)
  }

  const deleteCoreBlob = async () => {
    if (!(await confirmBox(T('cor_del_blob_q'), T('confirm_del')))) return
    setCoreMsg({ cls: '', text: T('cor_deleting') })
    const r = await apiPost('core-delete-blob', {})
    if (!(r.ok && r.d.ok)) {
      setCoreMsg(null)
      alertBox(postError(r))
      return
    }
    setCoreMsg({ cls: 'ok', text: T('cor_del_blob_ok') })
    setWanted((prev) => (prev === 'custom' ? '' : prev))
    await loadCoreVersions()
  }

  const pushCore = (id) => push.start('update-core', wanted ? { ids: [id], version: wanted } : { ids: [id] }, [id])

  const pushCoreAll = async () => {
    if (!wanted) {
      toast(T(coreUnknown ? 'net_read' : 'ag_pick_ver'), 'err')
      return
    }
    const ids = await onlineIds()
    if (!ids) return
    if (!ids.length) {
      toast(T('ag_no_online'), 'err')
      return
    }
    const ok = await confirmBox(
      T('ag_confirm_core') + coreVersionName(wanted) + T('ag_confirm_core2') + ids.length + T('ag_confirm_core3'),
      T('yes_all')
    )
    if (!ok) return
    await push.start('update-core', { ids, version: wanted }, ids)
  }

  const saveDownloadProxy = async () => {
    if (!proxies.length) {
      setProxyMsg(null)
      alertBox(T('dlpx_none'))
      return
    }
    const body = proxyBody(dlProxy)
    const r = await apiPost('settings-set', {
      dl_proxy_on: body.proxy_on,
      dl_proxy_id: body.proxy_id,
    })
    if (r.ok && r.d.ok) {
      setProxyMsg({ cls: 'ok', text: T('set_saved') })
      return
    }
    setProxyMsg(null)
    alertBox(postError(r))
  }

  const agentReady = agentMeta && !agentMeta.none
  const hasCustom = !coreUnknown && versions.some((v) => v.custom)
  const stagedArch = (staged && staged.arches && staged.arches[0]) || 'amd64'
  const stagedSha = (staged && staged.sha && staged.sha[stagedArch]) || ''
  const stagedSize = (staged && staged.size && staged.size[stagedArch]) || 0
  const pushNodes = (push.state && push.state.nodes) || {}

  return (
    <>
      {headless ? null : <PageHead icon="server" titleKey="ag_title" subKey="ag_sub" />}

      <div className="opgrid">
        <div className="card opc sc-panel">
          <div className="ophd">
            <span className="sgt">
              <Icon name="server" />
            </span>
            <b>{T('ag_node_agent')}</b>
            <span className="grow" />
            <span>
              {agentUnknown ? null : (
                <span className={'badge ' + (agentReady ? 'ok' : 'na')}>
                  {agentReady ? T('ag_ready') : T('ag_empty')}
                </span>
              )}
            </span>
          </div>
          <Meta>
            {agentReady ? (
              <>
                <span>{T('ag_word_agent')}</span>
                <span className="mono">v{num(agentMeta.version)}</span>
                <span className="sep" />
                <span className="mono">{String(agentMeta.sha256 || '').slice(0, 12)}</span>
                <span className="sep" />
                <span>
                  {Math.round(num(agentMeta.size) / 1024)} {T('unit_kb')}
                </span>
              </>
            ) : (
              <span className="muted">{T(agentUnknown ? 'loading' : 'ag_no_agent_loaded')}</span>
            )}
          </Meta>
          <div className="oprow">
            <button className="primary" disabled={gitBusy} onClick={fetchAgentFromGit}>
              <Icon name="redo" />
              {T('ag_fetch_git')}
            </button>
            <button className="ghost" onClick={() => agentFile.current.click()}>
              <Icon name="plus" />
              {T('ag_file_btn')}
            </button>
          </div>
          <DeliverySegment value={delivery.agent} onChange={(v) => changeDelivery('agent', v)} />
          <Message value={gitMsg} />
          <Message value={agentMsg} />
          <input
            type="file"
            accept=".py"
            ref={agentFile}
            style={{ display: 'none' }}
            onChange={(e) => uploadAgentFile(e.target)}
          />
          <button className="primary opgo" onClick={() => pushAgent('all')}>
            <Icon name="redo" />
            {T('ag_push_all')}
          </button>
        </div>

        <div className="card opc sc-perf">
          <div className="ophd">
            <span className="sgt">
              <Icon name="cpu" />
            </span>
            <b>{T('ag_data_core')}</b>
            <span className="grow" />
            <span>
              {coreUnknown ? null : (
                <span className={'badge ' + (!staged ? 'na' : coreReady.ready ? 'ok' : 'warn')}>
                  {T(!staged ? 'ag_empty' : coreReady.ready ? 'ag_ready' : 'ag_not_ready')}
                </span>
              )}
            </span>
          </div>
          <Meta>
            {staged ? (
              <>
                <span>{T('ag_word_core')}</span>
                <span className="mono">{staged.version}</span>
                {stagedSha ? (
                  <>
                    <span className="sep" />
                    <span className="mono">{String(stagedSha).slice(0, 12)}</span>
                  </>
                ) : null}
                {stagedSize ? (
                  <>
                    <span className="sep" />
                    <span>
                      {(stagedSize / 1048576).toFixed(1)} {T('unit_mb_full')}
                    </span>
                  </>
                ) : null}
                {(staged.arches || []).length ? (
                  <>
                    <span className="sep" />
                    <span>{staged.arches.join(' · ')}</span>
                  </>
                ) : null}
              </>
            ) : (
              <span className="muted">{T(coreUnknown ? 'loading' : 'ag_no_core_staged')}</span>
            )}
          </Meta>
          {staged && !coreReady.ready && coreReady.missing.length ? (
            <div className="muted" style={{ fontSize: 12 }}>
              {T('cor_not_ready').replace('{a}', coreReady.missing.join('، '))}
            </div>
          ) : null}

          <div className="oprow">
            <div id="cor_ver_box">
              {!coreUnknown && versions.length ? (
                <Select
                  items={versions.map((v) => ({ v: v.id, label: v.label || v.id }))}
                  value={wanted}
                  placeholder={T('ag_pick_version')}
                  onChange={setWanted}
                />
              ) : (
                <div className="muted" style={{ fontSize: 12 }}>
                  {T(coreUnknown ? 'loading' : 'cor_ver_empty')}
                </div>
              )}
            </div>
            <button type="button" className="ghost corcheck" onClick={checkCore}>
              <Icon name="redo" />
              {T('cor_check')}
            </button>
          </div>

          <div className="oprow">
            <button className="primary acc2" onClick={stageCore}>
              <Icon name="redo" />
              {T(delivery.core === 'github' ? 'cor_pick_git' : 'ag_fetch_git')}
            </button>
            <button className="ghost" onClick={() => coreFile.current.click()}>
              <Icon name="plus" />
              {T('ag_binary')}
            </button>
            {hasCustom ? (
              <button className="ghost opdel" title={T('cor_del_blob')} onClick={deleteCoreBlob}>
                <Icon name="trash" />
              </button>
            ) : null}
          </div>

          <DeliverySegment value={delivery.core} onChange={(v) => changeDelivery('core', v)} />
          <Message value={coreMsg} onCancel={cancelStage} />
          <input
            type="file"
            ref={coreFile}
            style={{ display: 'none' }}
            onChange={(e) => uploadCoreBinary(e.target)}
          />
          <button className="primary opgo acc2" onClick={pushCoreAll}>
            <Icon name="redo" />
            {T('ag_install_all')}
          </button>
        </div>
      </div>

      <div className="card opc sc-conn" style={{ marginTop: 14 }}>
        <div className="ophd">
          <span className="sgt">
            <Icon name="shield" />
          </span>
          <b>{T('dlpx_title')}</b>
        </div>
        <Meta>
          <span className="muted">{T('dlpx_sub')}</span>
        </Meta>
        {dlProxy ? (
          proxies.length ? (
            <ProxyFields
              proxies={proxies}
              value={dlProxy}
              onChange={setDlProxy}
              labelKey="dlpx_on"
              subKey="dlpx_via"
            />
          ) : (
            <div className="muted" style={{ fontSize: 12 }}>
              {T('dlpx_none')}
            </div>
          )
        ) : dlError ? (
          <div className="msg loadfail">
            <span>{T('dlpx_load_fail') + ' ' + dlError}</span>
            <button type="button" className="ghost" onClick={loadDlProxy}>
              <Icon name="redo" />
              {T('retry')}
            </button>
          </div>
        ) : null}
        <Message value={proxyMsg} />
        {dlProxy ? (
          <button className="primary opgo" onClick={saveDownloadProxy}>
            <Icon name="redo" />
            {T('save')}
          </button>
        ) : null}
      </div>

      <div className="sec" style={{ marginTop: 16 }}>
        <Icon name="server" color="var(--acc)" />
        {T('nodes_fleet')}
      </div>

      <Toolbar value={query} placeholder={T('ag_search')} onSearch={setQuery} />

      <div id="agList">
        {nodes === null ? (
          <AgentRowsSkeleton count={counts.nodes_total} />
        ) : nodes.length ? (
          nodes.map((node) => (
            <AgentNodeRow
              key={node.id}
              node={node}
              agentMeta={agentMeta}
              agentFromGit={delivery.agent === 'github'}
              staged={staged}
              wanted={wanted}
              status={pushNodes[node.id] || (push.seeded[node.id] ? { state: 'run', pct: 0, step: 'start', si: 0, sn: 1, remote: true } : null)}
              onPushAgent={pushAgent}
              onPushCore={pushCore}
            />
          ))
        ) : (
          <div className="card muted">{T('ag_no_item')}</div>
        )}
      </div>

      <div id="pushFab">
        <PushFab
          state={push.state}
          onPause={() => push.pause(true)}
          onResume={() => push.pause(false)}
          onCancel={push.cancel}
        />
      </div>
    </>
  )
}
