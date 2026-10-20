import Icon from '../../components/Icon.jsx'
import { linkSideState, movedTo } from './sideHealth.js'
import { TF } from '../../i18n/fa.js'

export default function SideDot({ link, side }) {
  if (movedTo(link, side)) {
    const said = TF('drift_one', { a: link[side + '_name'] })
    return (
      <span className="sdotw" role="img" aria-label={said} title={said}>
        <Icon name="warn" />
      </span>
    )
  }
  const state = linkSideState(link, side)
  return <span className={'sdot ' + state.kind} title={state.title} />
}
