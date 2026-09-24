import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import CopyValue, { copyText } from '../../components/CopyValue.jsx'
import RichText from '../../components/RichText.jsx'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { pressable } from '../../lib/keys.js'
import { T, TF } from '../../i18n/fa.js'
import { DOCS, GROUPS, SAMPLES } from './apiDocs.js'
import './apiref.css'

const G = SAMPLES._generic
const CODES = [200, 400, 401, 403, 404, 405, 413, 429, 500, 503]

function quote(s) {
  return "'" + s.replace(/'/g, "'\\''") + "'"
}

function curlOf(base, cmd, method, sample) {
  if (method === 'GET') {
    const q = sample.q ? '?' + new URLSearchParams(sample.q).toString() : ''
    return 'curl -H "Authorization: Bearer $TOKEN" ' + quote(base + cmd + q)
  }
  return [
    'curl -X POST ' + quote(base + cmd),
    '  -H "Authorization: Bearer $TOKEN"',
    '  -H "Content-Type: application/json"',
    '  -d ' + quote(JSON.stringify(sample.req || {})),
  ].join(' \\\n')
}

function answers(cmd, method, token, act) {
  const s = SAMPLES[cmd] || {}
  const errs = s.errs || []
  const out = []
  const add = (key, code, note, bodies, sub) => {
    if (bodies.length) out.push({ key, code, note, bodies, sub })
  }
  add('ok', 200, T('api_c_200'), s.ok ? [s.ok] : [])
  if (act) add('act', 'acts', T('api_c_act'), [SAMPLES._acts.done, SAMPLES._acts.fail])
  add('soft', 200, T('api_c_soft'), errs.filter((e) => e.status === 200).map((e) => e.resp), 'ok:false')
  add('400', 400, T('api_c_400'), errs.filter((e) => e.status === 400).map((e) => e.resp))
  add('401', 401, T('api_c_401'), [G['401'].resp, G['401b'].resp])
  add('403', 403, T('api_c_403'), token ? [G['403'].resp] : [G['403d'].resp, G['403'].resp])
  if (method === 'POST') {
    add('405', 405, T('api_c_405'), [G['405'].resp])
    add('413', 413, T('api_c_413'), [G['413'].resp])
  }
  add('429', 429, T('api_c_429'), [G['429'].resp])
  add('500', 500, T('api_c_500'), [G['500'].resp, G['500i'].resp])
  add('503', 503, T('api_c_503'), [G['503'].resp])
  return out
}

function tone(code) {
  if (code === 'acts') return 'acts'
  if (code < 300) return 'c2'
  if (code < 500) return 'c4'
  return 'c5'
}

function Json({ value }) {
  return <pre className="apjs mono">{JSON.stringify(value, null, 2)}</pre>
}

function Body({ cmd, method, token, base }) {
  const doc = DOCS[cmd] || {}
  const sample = SAMPLES[cmd] || {}
  const list = answers(cmd, method, token, doc.act)
  const [pick, setPick] = useState(list[0].key)
  const cur = list.find((a) => a.key === pick) || list[0]
  const params = doc.p || []
  const curl = token ? curlOf(base, cmd, method, sample) : ''

  return (
    <div className="apbody">
      {doc.d ? <p className="apdesc">{doc.d}</p> : null}
      {token ? null : <p className="apwarn">{T('api_deny_d')}</p>}

      <h5>{method === 'GET' ? T('api_p_query') : T('api_p_body')}</h5>
      {params.length ? (
        <div className="aprms">
          {params.map(([name, req, type, text]) => (
            <div className="aprm" key={name}>
              <div className="aprmh">
                <code className="mono">{name}</code>
                <span className="aptype mono">{type}</span>
                {req ? <span className="apreq">{T('api_req')}</span> : null}
              </div>
              <div className="aprmd">{text}</div>
            </div>
          ))}
        </div>
      ) : (
        <p className="apnone">{T('api_p_none')}</p>
      )}

      {curl ? (
        <>
          <h5>
            {T('api_example')}
            <button type="button" className="apcopy" title={T('tip_copy')} onClick={(e) => copyText(curl, e)}>
              <Icon name="copy" />
            </button>
          </h5>
          <pre className="apjs mono">{curl}</pre>
        </>
      ) : method === 'POST' && sample.req ? (
        <>
          <h5>{T('api_example_body')}</h5>
          <Json value={sample.req} />
        </>
      ) : null}

      <h5>{T('api_answers')}</h5>
      <div className="apcodes">
        {list.map((a) => (
          <button
            type="button"
            key={a.key}
            className={'apcc ' + tone(a.code) + (a.key === cur.key ? ' on' : '')}
            aria-pressed={a.key === cur.key}
            onClick={() => setPick(a.key)}
          >
            {a.code}
            {a.sub ? <small>{a.sub}</small> : null}
          </button>
        ))}
      </div>
      <p className="apcnote">{cur.note}</p>
      {cur.bodies.map((b, i) => (
        <Json key={i} value={b} />
      ))}
    </div>
  )
}

function Row({ cmd, method, token, open, onToggle, base }) {
  const doc = DOCS[cmd] || {}
  return (
    <div className={'apep' + (open ? ' open' : '')}>
      <div className="apsum" aria-expanded={open ? 'true' : 'false'} {...pressable(onToggle)}>
        <span className={'apm ' + method.toLowerCase()}>{method}</span>
        <code className="appath mono">/api/{cmd}</code>
        <span className="apt">{doc.t || ''}</span>
        {token ? null : <span className="apdeny">{T('api_deny')}</span>}
        <Icon name="chev" />
      </div>
      {open ? <Body cmd={cmd} method={method} token={token} base={base} /> : null}
    </div>
  )
}

function matches(cmd, q) {
  if (!q) return true
  const doc = DOCS[cmd] || {}
  return [cmd, doc.t || '', doc.d || ''].some((v) => v.toLowerCase().includes(q))
}

export default function ApiRef() {
  const { api } = useUiConfig()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(() => new Set())
  const base = window.location.origin + '/api/'
  const meta = new Map(api.map(([cmd, method, token]) => [cmd, { method, token }]))
  const placed = new Set(GROUPS.flatMap(([, , cmds]) => cmds))
  const rest = api.map(([cmd]) => cmd).filter((cmd) => !placed.has(cmd))
  const q = query.trim().toLowerCase()
  const groups = [...GROUPS, ['other', T('api_other'), rest]]
    .map(([id, title, cmds]) => [id, title, cmds.filter((c) => meta.has(c) && matches(c, q))])
    .filter(([, , cmds]) => cmds.length)

  const toggle = (cmd) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(cmd)) next.delete(cmd)
      else next.add(cmd)
      return next
    })

  return (
    <div className="card sg sc-panel apref">
      <div className="sghd">
        <span className="sgt">
          <Icon name="list" />
        </span>
        <b>{T('api_ref')}</b>
        <span className="schip">{TF('api_ref_n', { n: api.length })}</span>
      </div>

      <div className="apguide">
        <div className="apbase">
          <span>{T('api_base')}</span>
          <CopyValue text={base} />
        </div>
        {['api_g_auth', 'api_g_req', 'api_g_res', 'api_g_act', 'api_g_deny'].map((k) => (
          <p key={k}>
            <RichText text={T(k)} />
          </p>
        ))}
        <h5>{T('api_codes')}</h5>
        <div className="apctab">
          {CODES.map((c) => (
            <div key={c} className="apcrow">
              <span className={'apcc ' + tone(c)}>{c}</span>
              <span>{T('api_c_' + c)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="aplist">
        <input
          className="search"
          placeholder={T('api_search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {groups.length ? (
          groups.map(([id, title, cmds]) => (
            <div className="apgrp" key={id}>
              <div className="apgh">
                <b>{title}</b>
                <i>{cmds.length}</i>
              </div>
              {cmds.map((cmd) => (
                <Row
                  key={cmd}
                  cmd={cmd}
                  method={meta.get(cmd).method}
                  token={meta.get(cmd).token}
                  open={open.has(cmd)}
                  onToggle={() => toggle(cmd)}
                  base={base}
                />
              ))}
            </div>
          ))
        ) : (
          <p className="apnone">{T('api_empty')}</p>
        )}
      </div>
    </div>
  )
}
