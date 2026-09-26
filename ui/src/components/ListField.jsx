import { useLayoutEffect, useRef, useState } from 'react'
import Icon from './Icon.jsx'
import NumberInput, { cleanNumber } from './NumberInput.jsx'
import { T, TF } from '../i18n/fa.js'
import { EASE_OUT, reducedMotion } from '../lib/motion.js'

const SEP = /[\s,،]+/

function split(text) {
  return cleanNumber(text, 'list').split(SEP).filter(Boolean)
}

function chipKeys(items) {
  const seen = {}
  return items.map((n) => {
    seen[n] = (seen[n] || 0) + 1
    return n + '#' + seen[n]
  })
}

function ghostOut(root, el, rect) {
  const base = root.getBoundingClientRect()
  const ghost = el.cloneNode(true)
  ghost.setAttribute('aria-hidden', 'true')
  ghost.inert = true
  Object.assign(ghost.style, {
    position: 'absolute',
    margin: '0',
    pointerEvents: 'none',
    left: rect.left - base.left + 'px',
    top: rect.top - base.top + 'px',
    width: rect.width + 'px',
  })
  root.appendChild(ghost)
  ghost
    .animate([{ opacity: 1, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(.9)' }], {
      duration: 140,
      easing: EASE_OUT,
      fill: 'forwards',
    })
    .finished.then(
      () => ghost.remove(),
      () => ghost.remove()
    )
}

export default function ListField({ value, onChange, range, ...rest }) {
  const [draft, setDraft] = useState('')
  const input = useRef(null)
  const box = useRef(null)
  const flip = useRef(null)
  const items = split(value)
  const keys = chipKeys(items)
  const [lo, hi] = range

  const commit = (text) => {
    const added = split(text).map((n) => String(Number(n)))
    setDraft('')
    if (added.length) onChange([...items, ...added].join(', '))
  }

  useLayoutEffect(() => {
    const f = flip.current
    flip.current = null
    if (!f) return
    const root = box.current
    ghostOut(root, f.gone, f.rects.get(f.gone))
    for (const el of root.children) {
      const was = f.rects.get(el)
      if (!was) continue
      el.getAnimations().forEach((a) => a.cancel())
      const now = el.getBoundingClientRect()
      const dx = was.left - now.left
      const dy = was.top - now.top
      if (!dx && !dy) continue
      el.animate([{ transform: 'translate(' + dx + 'px,' + dy + 'px)' }, { transform: 'none' }], {
        duration: 200,
        easing: EASE_OUT,
      })
    }
  }, [value])

  const remove = (index, e) => {
    if (e.detail && !reducedMotion()) {
      const kids = [...box.current.children]
      flip.current = { gone: kids[index], rects: new Map(kids.map((el) => [el, el.getBoundingClientRect()])) }
    }
    onChange(items.filter((_, i) => i !== index).join(', '))
    if (!e.detail) input.current.focus()
  }

  return (
    <div className="lstf" ref={box}>
      {items.map((n, i) => (
        <button
          key={keys[i]}
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
