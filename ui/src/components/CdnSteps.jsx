import Icon from './Icon.jsx'

export default function CdnSteps({ steps }) {
  if (!steps || !steps.length) return null
  return (
    <ol className="cdnsteps">
      {steps.map((s, i) => (
        <li key={i} className={s.st}>
          <Icon name={s.st === 'ok' ? 'okc' : 'info'} />
          <span>{s.t}</span>
        </li>
      ))}
    </ol>
  )
}
