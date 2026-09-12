import { num } from './num.js'

export const CARD_TAGS = [
  { a: '#9DE02E', b: '#39D74C' },
  { a: '#21D6DF', b: '#36ABFA' },
  { a: '#37E9C7', b: '#45C9EF' },
  { a: '#FDB61E', b: '#F77F43' },
  { a: '#F68C38', b: '#F75968' },
  { a: '#E46DC9', b: '#A673FC' },
]

export function tagClass(link) {
  const tag = num(link.tag)
  return tag >= 1 && tag <= CARD_TAGS.length ? ' tagd' : ''
}

export function tagStyle(tag) {
  const colors = CARD_TAGS[num(tag) - 1]
  return colors ? { '--tga': colors.a, '--tgb': colors.b } : undefined
}
