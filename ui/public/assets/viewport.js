(() => {
  const cancel = event => event.preventDefault()
  const options = { capture: true, passive: false }

  window.addEventListener('gesturestart', cancel, options)
  window.addEventListener('gesturechange', cancel, options)
  window.addEventListener('wheel', event => {
    if (event.ctrlKey || event.metaKey) event.preventDefault()
  }, options)
  window.addEventListener('keydown', event => {
    if ((!event.ctrlKey && !event.metaKey) || event.altKey) return
    if (['+', '=', '-'].includes(event.key) || ['Equal', 'Minus', 'NumpadAdd', 'NumpadSubtract'].includes(event.code)) {
      event.preventDefault()
    }
  }, true)
})()
