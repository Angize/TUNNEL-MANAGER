const BOLD = /<b>(.*?)<\/b>/gs

export default function RichText({ text }) {
  const source = String(text == null ? '' : text)
  const parts = []
  let last = 0
  let match

  BOLD.lastIndex = 0
  while ((match = BOLD.exec(source)) !== null) {
    if (match.index > last) parts.push(source.slice(last, match.index))
    parts.push(<b key={match.index}>{match[1]}</b>)
    last = match.index + match[0].length
  }
  if (last < source.length) parts.push(source.slice(last))

  return parts
}
