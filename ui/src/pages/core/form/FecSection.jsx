import { TglBox, Tile, Tiles } from './controls.jsx'
import { fecDatagram } from './gates.js'
import { fecRates } from './presets.js'
import { T } from '../../../i18n/fa.js'

export default function FecSection({ form, patch }) {
  if (!fecDatagram(form)) return null

  return (
    <>
      <TglBox
        on={!!form.Fec}
        title={T('fec_t')}
        note={T('fec_d')}
        gap={11}
        onClick={() => patch({ Fec: !form.Fec })}
      />
      {form.Fec ? (
        <div>
          <label>{T('fec_rate_lbl')}</label>
          <Tiles>
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
      ) : null}
    </>
  )
}
