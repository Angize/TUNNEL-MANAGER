import Modal from './Modal.jsx'
import { T } from '../i18n/fa.js'

export default function modalLoading({ icon, title, subtitle, cls, onClose }) {
  return (
    <Modal loading icon={icon} title={title} subtitle={subtitle} cls={cls} onClose={onClose}>
      <div className="mload">
        <span className="bspin" />
        <span>{T('loading')}</span>
      </div>
    </Modal>
  )
}
