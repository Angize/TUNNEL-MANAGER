import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
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
import { portErr } from './validate.js'
import { apiGet, apiPost } from '../../../lib/api.js'
import { alertBox } from '../../../lib/dialog.js'
import { postError, readError, translateError } from '../../../lib/errors.js'
import { toast } from '../../../lib/toast.js'
import { nodeIps } from '../../../lib/nodes.js'
import { subnetFitError, subnetForBase } from '../../../lib/subnet.js'
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
  const tabBase = useId()
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
      if (!link && reply.nodes.filter((n) => n.online && !n.hidden).length < 2) {
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
    const online = nodes.filter((n) => n.online && !n.hidden)
    const next = createForm(cfg)
    next.aNode = online[0].id
    next.bNode = online[1].id
    setForm(next)
  }, [nodes, form, link, cfg])

  const items = useMemo(() => {
    if (!nodes) return []
    if (link) return nodeItemsForEdit(nodes, link)
    return nodes
      .filter((n) => n.online && !n.hidden)
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

  const drawFor = !link && form && form.Tr !== 'raw' && form.Tr !== 'ws' ? form.Tr : ''

  useEffect(() => {
    if (!drawFor) return undefined
    let alive = true
    apiGet('next-port')
      .then((r) => {
        if (!alive) return
        setForm((f) =>
          f && (f.port === '' || f.portAuto) ? { ...f, port: String(r.port), portAuto: true } : f
        )
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [drawFor])

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
    const ips = nodeIps(nodes, value)
    const sel = form.rot.on && ips.length ? { [ips[0]]: true } : {}
    if (side === 'a') patch({ aNode: value, aIp: '', rot: { ...form.rot, aSel: sel } })
    else patch({ bNode: value, bIp: '', rot: { ...form.rot, bSel: sel } })
  }

  const stop = async (text, where) => {
    setMessage('')
    if (where) setTab(where)
    await alertBox(text)
  }

  const submit = async () => {
    setMessage('')
    if (form.aNode === form.bNode) {
      await stop(T('two_diff_nodes'), 'ip')
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
      await stop(carrierError, 'set')
      return
    }

    if (body.cover) {
      const sni = form.coverSni.trim()
      if (!sni) {
        await stop(T('cover_need_sni'), 'set')
        return
      }
      body.cover_sni = sni
    }

    const rotError = rotValidate(form, aIps, bIps)
    if (rotError) {
      await stop(rotError, 'ip')
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
      const subnet = (form.subnet || '').trim()
      if (!subnet) {
        await stop(T('snr_custom_need'), 'set')
        return
      }
      body.subnet = subnet
    } else if (link) {
      const fitError = subnetFitError('core', link.tunnel_id, form.range)
      if (fitError) {
        await stop(fitError, 'set')
        return
      }
      body.subnet = subnetForBase('core', link.tunnel_id, form.range)
    } else body.subnet_base = form.range

    const portError = portErr(form.port, cfg.limits)
    if (portError) {
      await stop(portError, 'set')
      return
    }

    if (form.Tr === 'ws' && !form.port) body.port = '80'
    else if (form.port) body.port = form.port
    else if (link && form.Tr !== 'raw') body.port = ''

    if (!link) setMessage(T('creating_core'))

    const r = await apiPost(link ? 'edit-link' : 'create-tunnel', body)
    if (!(r.ok && r.d.act)) {
      await stop(postError(r))
      return
    }
    const verdict = await waitAccepted(r.d.act, () => mounted.current)
    if (verdict.gone) return
    if (verdict.err || verdict.cancelled) {
      await stop(verdict.cancelled ? T('a_stopped') : translateError(verdict.err) || T('failed'))
      return
    }
    onClose()
    onDone()
  }

  const onTabKey = (e) => {
    const at = TABS.findIndex((entry) => entry.v === tab)
    const next = {
      ArrowLeft: (at + 1) % TABS.length,
      ArrowRight: (at + TABS.length - 1) % TABS.length,
      Home: 0,
      End: TABS.length - 1,
    }[e.key]
    if (next === undefined) return
    e.preventDefault()
    setTab(TABS[next].v)
    document.getElementById(tabBase + 't' + TABS[next].v).focus()
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
      <div className="ctabs" role="tablist" onKeyDown={onTabKey}>
        {TABS.map((entry) => (
          <button
            key={entry.v}
            id={tabBase + 't' + entry.v}
            type="button"
            role="tab"
            aria-selected={tab === entry.v ? 'true' : 'false'}
            aria-controls={tabBase + 'p' + entry.v}
            tabIndex={tab === entry.v ? 0 : -1}
            className={'ctab' + (tab === entry.v ? ' on' : '')}
            onClick={() => setTab(entry.v)}
          >
            <Icon name={entry.icon} />
            {entry.label()}
          </button>
        ))}
      </div>

      <div
        id={tabBase + 'pip'}
        role="tabpanel"
        aria-labelledby={tabBase + 'tip'}
        className={'ctabp' + (tab === 'ip' ? ' on' : '')}
      >
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
          patch={patch}
          onNode={onNode}
        />
      </div>

      <div
        id={tabBase + 'pset'}
        role="tabpanel"
        aria-labelledby={tabBase + 'tset'}
        className={'ctabp' + (tab === 'set' ? ' on' : '')}
      >
        <SettingsTab
          form={form}
          cfg={cfg}
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
