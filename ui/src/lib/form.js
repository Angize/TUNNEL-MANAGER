export const PORT_MAX = 65535

export const NO_AUTOFIX = { autoCapitalize: 'off', autoCorrect: 'off', spellCheck: false }

export const LTR_TEXT = { ...NO_AUTOFIX, dir: 'ltr', autoComplete: 'off' }

export function rangeLabel(label, lo, hi) {
  return label + ' (' + lo + '–' + hi + ')'
}
