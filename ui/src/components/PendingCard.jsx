import ActionRow from './ActionRow.jsx'
import { T } from '../i18n/fa.js'

const TITLE = { fail: 'a_pending_fail', cancel: 'a_pending_cancel' }

export default function PendingCard({ act, tagClass }) {
  const family = String(act.ttype || '').toLowerCase()
  return (
    <div className={'card acc open apend' + (act.state === 'run' ? ' acting' : '')}>
      <div className="chead" style={{ cursor: 'default' }}>
        <div className="hmain">
          <div className="hrow1">
            <span className="hname">{T(TITLE[act.state] || 'a_pending')}</span>
            {family ? <span className={'ctag ' + tagClass(family)}>{family.toUpperCase()}</span> : null}
            <span className="hpeers" dir="ltr">
              <span className="pn">{act.target || ''}</span>
            </span>
          </div>
        </div>
      </div>
      <div className="cbody">
        <div className="cbody-in">
          <ActionRow act={act} />
        </div>
      </div>
    </div>
  )
}
