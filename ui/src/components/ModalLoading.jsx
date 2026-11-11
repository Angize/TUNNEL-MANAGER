import Modal from './Modal.jsx'
import { SkelForm } from './Skeleton.jsx'

export default function modalLoading({ icon, title, subtitle, cls, onClose }) {
  return (
    <Modal loading icon={icon} title={title} subtitle={subtitle} cls={cls} onClose={onClose}>
      <SkelForm />
    </Modal>
  )
}
