import { useId, useState } from 'react'
import Icon from '../../components/Icon.jsx'

const labels = {
  tunnel_id: 'شناسهٔ تونل', subnet: 'زیرشبکه', enabled: 'وضعیت', transport: 'حامل',
  port: 'پورت', cipher: 'رمزنگاری', raw_profile: 'پروفایل ارسال', raw_profile_down: 'پروفایل دریافت',
  ws_host: 'میزبان', ws_path: 'مسیر', cdn_carrier: 'حامل شبکهٔ توزیع', fec: 'بازیابی بسته',
  fec_data: 'بسته‌های داده', fec_parity: 'بسته‌های جبرانی', obfs: 'استتار', gso: 'تجمیع بسته',
  cover: 'پوشش', ip_rotate: 'چرخش نشانی', a_ip_pool: 'نشانی‌های سر اول', b_ip_pool: 'نشانی‌های سر دوم',
  raw_port: 'پورت حامل', raw_sport: 'پورت مبدأ', a_workers: 'پردازشگرهای سر اول', b_workers: 'پردازشگرهای سر دوم', cover_sni: 'دامنهٔ پوشش',
  ws_tls: 'اتصال امن', raw_facade: 'پوشش پروتکل', ws_edge_ips: 'نشانی لبه‌ها', ws_rotate_secs: 'فاصلهٔ چرخش لبه'
}

function cellValue(value) {
  if (typeof value === 'boolean') return value ? 'فعال' : 'غیرفعال'
  return Array.isArray(value) ? value.join('، ') : String(value)
}

export default function TransferDetails({ tunnel }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const d = tunnel.details
  const firstServer = d.type !== 'core' || d.server_side !== 'b'
  const rows = [
    ['نوع تونل', tunnel.kind],
    ...['a', 'b'].flatMap((side, i) => {
      const server = i === 0 ? firstServer : !firstServer
      const label = d.type === 'core' ? server ? 'سرور' : 'کلاینت' : i ? 'سر دوم' : 'سر اول'
      return [[label, d[side + '_name']], ['نشانی ' + label, d[side + '_ip']],
        ['نشانی داخلی ' + label, d.overlay[i]]]
    }),
    ...Object.entries(labels).filter(([k]) => d[k] != null && d[k] !== '' && !(Array.isArray(d[k]) && !d[k].length))
      .map(([k,label]) => [label, cellValue(d[k])])
  ]
  return <>
    <button className="nt-details-btn" type="button" aria-expanded={open} aria-controls={id}
      aria-label={(open ? 'بستن' : 'نمایش') + ' جزئیات ' + tunnel.name} onClick={() => setOpen(!open)}>
      جزئیات <Icon name="chev" /></button>
    <dl id={id} className="nt-specs" hidden={!open}>{rows.map(([key,value]) =>
      <div key={key}><dt>{key}</dt><dd><bdi>{value}</bdi></dd></div>)}</dl>
  </>
}
