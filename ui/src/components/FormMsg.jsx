import Msg from './Msg.jsx'
import './formmsg.css'

export default function FormMsg({ text }) {
  return (
    <div className="fmsg">
      <Msg text={text} />
    </div>
  )
}
