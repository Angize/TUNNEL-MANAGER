import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import CopyValue, { copyText } from '../../components/CopyValue.jsx'
import RichText from '../../components/RichText.jsx'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { pressable } from '../../lib/keys.js'
import { DOCS, GROUPS, SAMPLES, TEXT } from './apiDocs.js'
import ERRS from './apiErrors.json'
import './apiref.css'

const G = SAMPLES._generic
const CODES = [200, 400, 401, 403, 404, 405, 413, 429, 500, 503]
const PLACED = new Set(GROUPS.flatMap(([, , cmds]) => cmds))

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
  const e = ERRS[cmd] || {}
  const out = []
  const add = (key, code, note, bodies, rows, sub) => {
    if (bodies.length || rows.length) out.push({ key, code, note, bodies, rows, sub })
  }
  add('ok', 200, TEXT.c[200], s.ok ? [s.ok] : [], [])
  if (act) add('act', 'acts', TEXT.c.act, [SAMPLES._acts.done, SAMPLES._acts.fail], e.act || [])
  add('soft', 200, TEXT.c.soft, [], e.soft || [], 'ok:false')
  add('400', 400, TEXT.c[400], [], e.bad || [])
  add('401', 401, TEXT.c[401], [], G['401'])
  add('403', 403, TEXT.c[403], [], token ? G['403'] : [...G['403d'], ...G['403']])
  if (method === 'POST') {
    add('405', 405, TEXT.c[405], [], G['405'])
    add('413', 413, TEXT.c[413], [], G['413'])
  }
  add('429', 429, TEXT.c[429], [], G['429'])
  add('500', 500, TEXT.c[500], [], G['500'])
  add('503', 503, TEXT.c[503], [], G['503'])
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

function row([code, error]) {
  return '{"code": ' + JSON.stringify(code) + ', "error": ' + JSON.stringify(error) + '}'
}

function Rows({ rows }) {
  return <pre className="apjs mono">{rows.map(row).join('\n')}</pre>
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
      {token ? null : <p className="apwarn">{TEXT.denyD}</p>}

      <h5>{method === 'GET' ? TEXT.pQuery : TEXT.pBody}</h5>
      {params.length ? (
        <div className="aprms">
          {params.map(([name, req, type, text]) => (
            <div className="aprm" key={name}>
              <div className="aprmh">
                <code className="mono">{name}</code>
                <span className="aptype mono">{type}</span>
                {req ? <span className="apreq">{TEXT.req}</span> : null}
              </div>
              <div className="aprmd">{text}</div>
            </div>
          ))}
        </div>
      ) : (
        <p className="apnone">{TEXT.pNone}</p>
      )}

      {curl ? (
        <>
          <h5>
            {TEXT.example}
            <button type="button" className="apcopy" title={TEXT.copy} onClick={(e) => copyText(curl, e)}>
              <Icon name="copy" />
            </button>
          </h5>
          <pre className="apjs mono">{curl}</pre>
        </>
      ) : method === 'POST' && sample.req ? (
        <>
          <h5>{TEXT.exampleBody}</h5>
          <Json value={sample.req} />
        </>
      ) : null}

      <h5>{TEXT.answers}</h5>
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
      {cur.rows.length ? (
        <>
          <p className="apcnote">{cur.bodies.length ? TEXT.rowsAct : TEXT.rowsAll}</p>
          <Rows rows={cur.rows} />
        </>
      ) : null}
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
        {token ? null : <span className="apdeny">{TEXT.deny}</span>}
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
  const rest = api.map(([cmd]) => cmd).filter((cmd) => !PLACED.has(cmd))
  const q = query.trim().toLowerCase()
  const groups = [...GROUPS, ['other', TEXT.other, rest]]
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
    <div className="card sg sc-panel apref" dir="ltr">
      <div className="sghd">
        <span className="sgt">
          <Icon name="list" />
        </span>
        <b>{TEXT.ref}</b>
        <span className="schip">{TEXT.refN.replace('{n}', api.length)}</span>
      </div>

      <div className="apguide">
        <div className="apbase">
          <span>{TEXT.base}</span>
          <CopyValue text={base} />
        </div>
        {TEXT.guide.map((text) => (
          <p key={text}>
            <RichText text={text} />
          </p>
        ))}
        <h5>{TEXT.codes}</h5>
        <div className="apctab">
          {CODES.map((c) => (
            <div key={c} className="apcrow">
              <span className={'apcc ' + tone(c)}>{c}</span>
              <span>{TEXT.c[c]}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="aplist">
        <input
          className="search"
          placeholder={TEXT.search}
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
          <p className="apnone">{TEXT.empty}</p>
        )}
      </div>
    </div>
  )
}
