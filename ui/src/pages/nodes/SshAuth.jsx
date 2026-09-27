import Field from '../../components/Field.jsx'
import Reveal from '../../components/Reveal.jsx'
import { T } from '../../i18n/fa.js'
import { LTR_TEXT } from '../../lib/form.js'

const MODES = [
  ['pass', 'nadd_pass'],
  ['key', 'nadd_privkey'],
]

export default function SshAuth({ mode, onMode, pass, onPass, sshKey, onKey, passHint, keyHint }) {
  return (
    <div className="authbox">
      <div className="authhd">
        <span className="t">{T('nadd_ssh_auth')}</span>
        <span className="authseg" role="radiogroup" aria-label={T('nadd_ssh_auth')}>
          {MODES.map(([m, label]) => (
            <button
              key={m}
              type="button"
              role="radio"
              aria-checked={mode === m ? 'true' : 'false'}
              className={mode === m ? 'on' : undefined}
              onClick={() => onMode(m)}
            >
              {T(label)}
            </button>
          ))}
        </span>
      </div>
      <Reveal show={mode === 'pass'}>
        <Field hint={passHint}>
          <input
            className="fld2"
            type="password"
            autoComplete="new-password"
            aria-label={T('nadd_pass_word')}
            placeholder={T('nadd_pass_ph')}
            value={pass}
            onChange={(e) => onPass(e.target.value)}
          />
        </Field>
      </Reveal>
      <Reveal show={mode === 'key'}>
        <Field hint={keyHint}>
          <textarea
            className="fld2"
            rows={3}
            {...LTR_TEXT}
            aria-label={T('nadd_privkey')}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            value={sshKey}
            onChange={(e) => onKey(e.target.value)}
          />
        </Field>
      </Reveal>
    </div>
  )
}
