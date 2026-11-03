import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import { T } from '../../i18n/fa.js'
import { rangeLabel } from '../../lib/form.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

export default function PortField({ type, value, onChange }) {
  const { limits } = useUiConfig()
  const vxlan = type === 'vxlan'
  return (
    <Field
      label={rangeLabel(T('ttype_port_lbl'), ...limits.port)}
      hint={T(vxlan ? 'ttype_vxlan_note' : 'ttype_l2_note')}
    >
      <NumberInput
        placeholder={T(vxlan ? 'ttype_vxlan_ph' : 'ttype_port_ph')}
        value={value}
        onChange={onChange}
      />
    </Field>
  )
}
