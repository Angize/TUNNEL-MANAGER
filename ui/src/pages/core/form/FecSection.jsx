import { Tile, Tiles } from './controls.jsx'
import Reveal from '../../../components/Reveal.jsx'
import SwitchRow from '../../../components/SwitchRow.jsx'
import { fecDatagram } from './gates.js'
import { fecRates } from './presets.js'
import { T } from '../../../i18n/fa.js'

function Fec({ form, patch }) {
  return (
    <>
      <SwitchRow
        on={!!form.Fec}
        title={T('fec_t')}
        note={T('fec_d')}
        onToggle={() => patch({ Fec: !form.Fec })}
      />
      <Reveal show={!!form.Fec}>
        <div>
          <label>{T('fec_rate_lbl')}</label>
          <Tiles label={T('fec_rate_lbl')}>
            {fecRates().map((rate) => (
              <Tile
                key={rate.d + '+' + rate.p}
                on={rate.d === form.FecData && rate.p === form.FecParity}
                name={rate.d + '+' + rate.p}
                meta={rate.n}
                extra={rate.ov}
                onClick={() => patch({ FecData: rate.d, FecParity: rate.p })}
              />
            ))}
          </Tiles>
          <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 6 }}>
            {T('fec_note')}
          </div>
        </div>
      </Reveal>
    </>
  )
}

export default function FecSection(props) {
  return (
    <Reveal show={fecDatagram(props.form)}>
      <Fec {...props} />
    </Reveal>
  )
}
