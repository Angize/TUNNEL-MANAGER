import { useRef, useState } from 'react'
import Icon from './Icon.jsx'
import NumberInput, { cleanNumber } from './NumberInput.jsx'
import { T, TF } from '../i18n/fa.js'

const SEP = /[\s,،]+/

function split(text) {
  return cleanNumber(text, 'list').split(SEP).filter(Boolean)
}

export default function ListField({ value, onChange, range, ...rest }) {
  const [draft, setDraft] = useState('')
  const input = useRef(null)
  const items = split(value)
  const [lo, hi] = range

  const commit = (text) => {
    const added = split(text).map((n) => String(Number(n)))
    setDraft('')
    if (added.length) onChange([...items, ...added].join(', '))
  }

  const remove = (index, e) => {
    onChange(items.filter((_, i) => i !== index).join(', '))
    if (!e.detail) input.current.focus()
  }

  return (
    <div className="lstf">
      {items.map((n, i) => (
        <button
          key={i}
          type="button"
          className={'lstchip' + (Number(n) >= lo && Number(n) <= hi ? '' : ' bad')}
          aria-label={TF('set_list_del', { n })}
          onClick={(e) => remove(i, e)}
        >
          {n}
          <Icon name="x" />
        </button>
      ))}
      <NumberInput
        {...rest}
        ref={input}
        kind="list"
        inputMode="numeric"
        value={draft}
        onChange={(text) => (SEP.test(text) ? commit(text) : setDraft(text))}
        onBlur={() => commit(draft)}
        onKeyDown={(e) => {
          if (e.key !== 'Enter') return
          e.preventDefault()
          commit(draft)
        }}
      />
      <button
        type="button"
        className="lstadd"
        aria-label={T('set_list_add')}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => {
          commit(draft)
          input.current.focus()
        }}
      >
        <Icon name="plus" />
      </button>
    </div>
  )
}
