import PageHead from '../components/PageHead.jsx'

export default function Pending({ icon, titleKey, subKey }) {
  return (
    <>
      <PageHead icon={icon} titleKey={titleKey} subKey={subKey} />
      <div className="card muted">این بخش هنوز منتقل نشده</div>
    </>
  )
}
