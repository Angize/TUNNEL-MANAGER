function activator(onPress, onMenu) {
  return (e) => {
    if (e.target !== e.currentTarget) return
    if (onMenu && (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10'))) {
      e.preventDefault()
      onMenu()
      return
    }
    if (e.key !== 'Enter' && e.key !== ' ') return
    e.preventDefault()
    onPress(e)
  }
}

export function pressable(onPress, onMenu) {
  return { role: 'button', tabIndex: 0, onClick: onPress, onKeyDown: activator(onPress, onMenu) }
}

export function checkable(role, on, onToggle, locked) {
  if (locked) return { role, 'aria-checked': on ? 'true' : 'false', 'aria-disabled': 'true' }
  return {
    role,
    'aria-checked': on ? 'true' : 'false',
    tabIndex: 0,
    onClick: onToggle,
    onKeyDown: activator(onToggle),
  }
}
