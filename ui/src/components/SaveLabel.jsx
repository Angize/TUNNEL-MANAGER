import Icon from './Icon.jsx'

export default function SaveLabel({ busy, saved, children }) {
  if (saved) {
    return (
      <span className="bdone">
        <Icon name="check" />
        <span>{saved}</span>
      </span>
    )
  }
  if (busy) return <span className="bspin" />
  return children
}
