import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Modal from '../../../components/Modal.jsx'
import ModalLoading from '../../../components/ModalLoading.jsx'
import Icon from '../../../components/Icon.jsx'
import IpsTab from './IpsTab.jsx'
import SettingsTab from './SettingsTab.jsx'
import normalise from './normalise.js'
import usePeerStatus from './usePeerStatus.js'
import usePoolStatus from './usePoolStatus.js'
import { collectCarrier, rotCollect, rotValidate } from './collect.js'
import { createForm, editForm, nodeCpus, nodeItemsForEdit, nodeLabel, pickedIp } from './state.js'
import { apiGet, apiPost } from '../../../lib/api.js'
import { alertBox } from '../../../lib/dialog.js'
import { postError, readError, translateError } from '../../../lib/errors.js'
import { toast } from '../../../lib/toast.js'
import { nodeIps } from '../../../lib/nodes.js'
import { subnetForBase } from '../../../lib/subnet.js'
import { useActs } from '../../../state/ActsContext.jsx'
import { useSummary } from '../../../state/SummaryContext.jsx'
import { useUiConfig } from '../../../state/UiConfigContext.jsx'
import useBusy from '../../../lib/useBusy.js'
import { T } from '../../../i18n/fa.js'
import '../coreform.css'

const TABS = [
  { v: 'ip', icon: 'pin', label: () => T('cor_tab_ips') },
  { v: 'set', icon: 'cog', label: () => T('cor_tab_set') },
]

export default function CoreFormModal({ link, onClose, onDone }) {
  const cfg = useUiConfig()
  const [busy, guard] = useBusy()
  const { waitAccepted } = useActs()
  const { subnetFree } = useSummary()
  const [nodes, setNodes] = useState(null)
  const [proxies, setProxies] = useState([])
  const [tab, setTab] = useState('ip')
  const [form, setForm] = useState(null)
  const [message, setMessage] = useState('')
  const mounted = useRef(true)
  const closeRef = useRef(onClose)

  closeRef.current = onClose

  const patch = useCallback((next) => setForm((f) => ({ ...f, ...next })), [])

  useEffect(
    () => () => {
      mounted.current = false
    },
    []
  )

  useEffect(() => {
    let alive = true
    const load = async () => {
      let reply
      try {
        reply = await apiGet('node-names')
      } catch (e) {
        if (!alive) return
        toast(readError(e), 'err')
        closeRef.current()
        return
      }
      if (!alive) return
      if (!link && reply.nodes.filter((n) => n.online).length < 2) {
        toast(T('node_min2'), 'err')
        closeRef.current()
        return
      }
      setNodes(reply.nodes)
    }
    load()
    apiGet('proxies')
      .then((r) => alive && setProxies(r.proxies))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [link])

  useEffect(() => {
    if (!nodes || form) return
    if (link) {
      setForm(editForm(cfg, link))
      return
    }
    const online = nodes.filter((n) => n.online)
    const next = createForm(cfg)
    next.aNode = online[0].id
    next.bNode = online[1].id
    setForm(next)
  }, [nodes, form, link, cfg])

  const items = useMemo(() => {
    if (!nodes) return []
    if (link) return nodeItemsForEdit(nodes, link)
    return nodes
      .filter((n) => n.online)
      .map((n) => ({ v: n.id, label: n.name, sub: n.host }))
  }, [nodes, link])

  const aIps = useMemo(() => (form ? nodeIps(nodes, form.aNode) : []), [nodes, form])
  const bIps = useMemo(() => (form ? nodeIps(nodes, form.bNode) : []), [nodes, form])

  const aKey = aIps.join(',')
  const bKey = bIps.join(',')

  const gateKey = form
    ? [
        form.Tr,
        form.RawProfile,
        form.Cdn,
        form.cipher,
        form.Ech,
        form.Fec,
        form.SportRandom,
        form.Sprot,
        form.pool.pool,
        aKey,
        bKey,
      ].join('|')
    : ''

  useEffect(() => {
    setForm((f) =>
      f ? normalise(f, cfg, aKey ? aKey.split(',') : [], bKey ? bKey.split(',') : []) : f
    )
  }, [gateKey, cfg, aKey, bKey])

  const wantsDrawnPort =
    !link && !!form && form.Tr !== 'raw' && form.Tr !== 'ws' && form.port === ''

  useEffect(() => {
    if (!wantsDrawnPort) return undefined
    let alive = true
    apiGet('next-port')
      .then((r) => {
        if (!alive) return
        setForm((f) => (f && f.port === '' ? { ...f, port: String(r.port) } : f))
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [wantsDrawnPort])

  const poolLid = link && link.ws_pool ? link.id : ''
  const peerLid = link && link.ip_rotate ? link.id : ''
  const poolLive = usePoolStatus(poolLid, !!(form && form.pool.pool))
  const peerLive = usePeerStatus(peerLid)

  if (!form) {
    return (
      <ModalLoading
        icon={link ? 'pen' : 'cpu'}
        title={T(link ? 'core_edit_t' : 'core_tun_t')}
        subtitle={link ? link.name : T('core_tun_sub')}
        cls="edit"
        onClose={onClose}
      />
    )
  }

  const sides = {
    a: { name: nodeLabel(items, form.aNode), cpus: nodeCpus(nodes, form.aNode) },
    b: { name: nodeLabel(items, form.bNode), cpus: nodeCpus(nodes, form.bNode) },
  }

  const onNode = (side, value) => {
    if (side === 'a') patch({ aNode: value, aIp: '', rot: { ...form.rot, aSel: {} } })
    else patch({ bNode: value, bIp: '', rot: { ...form.rot, bSel: {} } })
  }

  const submit = async () => {
    setMessage('')
    if (form.aNode === form.bNode) {
      await alertBox(T('two_diff_nodes'))
      return
    }

    const body = link
      ? {
          id: link.id,
          type: 'core',
          a_node: form.aNode,
          b_node: form.bNode,
          server_side: form.Srv,
          cipher: form.cipher,
          transport: form.Tr,
          obfs: form.Obfs,
          cover: form.Cover && form.Tr === 'tcp',
          gso: form.Gso,
        }
      : {
          a_node: form.aNode,
          b_node: form.bNode,
          type: 'core',
          server_side: form.Srv,
          cipher: form.cipher,
          transport: form.Tr,
          obfs: form.Obfs,
          cover: form.Cover && form.Tr === 'tcp',
          gso: form.Gso,
        }

    if (link) setMessage(T('saving_rebuild_both'))

    const carrierError = collectCarrier(form, cfg, body)
    if (carrierError) {
      setMessage('')
      await alertBox(carrierError)
      return
    }

    if (body.cover) {
      const sni = form.coverSni.trim()
      if (!sni) {
        setMessage('')
        await alertBox(T('cover_need_sni'))
        return
      }
      body.cover_sni = sni
    }

    const rotError = rotValidate(form, aIps, bIps)
    if (rotError) {
      setMessage('')
      await alertBox(rotError)
      return
    }

    const storedA = link ? link.a_ip || '' : ''
    const storedB = link ? link.b_ip || '' : ''
    const aIp = pickedIp(form, aIps, form.rot.aSel, form.aIp, storedA)
    if (aIp) body.a_ip = aIp
    const bIp = pickedIp(form, bIps, form.rot.bSel, form.bIp, storedB)
    if (bIp) body.b_ip = bIp

    const rot = rotCollect(form, aIps, bIps)
    if (link) body.ip_rotate = !!rot
    else if (rot) body.ip_rotate = true
    if (rot) {
      body.a_ip_pool = rot.a_ip_pool
      body.b_ip_pool = rot.b_ip_pool
      body.rotate_secs = rot.rotate_secs
    }

    if (form.range === 'custom') {
      const subnet = form.subnet
      if (subnet) body.subnet = subnet
    } else if (link) {
      const subnet = subnetForBase('core', link.tunnel_id, form.range)
      if (subnet) body.subnet = subnet
    } else body.subnet_base = form.range

    if (form.Tr === 'ws' && !form.port) body.port = '80'
    else if (form.port) body.port = form.port
    else if (link && form.Tr !== 'raw') body.port = ''

    if (!link) setMessage(T('creating_core'))

    const r = await apiPost(link ? 'edit-link' : 'create-tunnel', body)
    if (!(r.ok && r.d.act)) {
      setMessage('')
      await alertBox(postError(r))
      return
    }
    const verdict = await waitAccepted(r.d.act, () => mounted.current)
    if (verdict.gone) return
    if (verdict.err || verdict.cancelled) {
      setMessage('')
      await alertBox(
        verdict.cancelled ? T('a_stopped') : translateError(verdict.err) || T('failed')
      )
      return
    }
    onClose()
    onDone()
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(submit)}>
        {busy ? <span className="bspin" /> : T(link ? 'save_rebuild' : 'create_tun_btn')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon={link ? 'pen' : 'cpu'}
      title={T(link ? 'core_edit_t' : 'core_tun_t')}
      subtitle={link ? link.name : T('core_tun_sub')}
      footer={footer}
      cls="edit"
      onClose={onClose}
    >
      <div className="ctabs">
        {TABS.map((entry) => (
          <button
            key={entry.v}
            type="button"
            className={'ctab' + (tab === entry.v ? ' on' : '')}
            onClick={() => setTab(entry.v)}
          >
            <Icon name={entry.icon} />
            {entry.label()}
          </button>
        ))}
      </div>

      <div className={'ctabp' + (tab === 'ip' ? ' on' : '')}>
        <IpsTab
          form={form}
          cfg={cfg}
          items={items}
          aIps={aIps}
          bIps={bIps}
          storedA={link ? link.a_ip || '' : ''}
          storedB={link ? link.b_ip || '' : ''}
          subtitle={link ? link.name : ''}
          peer={peerLid ? peerLive : null}
          tuning={cfg.tuning_defaults}
          patch={patch}
          onNode={onNode}
        />
      </div>

      <div className={'ctabp' + (tab === 'set' ? ' on' : '')}>
        <SettingsTab
          form={form}
          cfg={cfg}
          tuning={cfg.tuning_defaults}
          link={link}
          proxies={proxies}
          sides={sides}
          subnetFree={subnetFree}
          poolLive={{ ...poolLive, lid: poolLid }}
          patch={patch}
        />
      </div>

      <div className="msg">{message}</div>
    </Modal>
  )
}
