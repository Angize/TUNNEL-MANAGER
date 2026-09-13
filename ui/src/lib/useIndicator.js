import { useLayoutEffect, useState } from 'react'

export default function useIndicator(box, active, axis) {
  const [style, setStyle] = useState(null)

  useLayoutEffect(() => {
    const place = () => {
      const el = box.current && box.current.querySelector('.on')
      if (!el) {
        setStyle(null)
        return
      }
      setStyle(
        axis === 'x'
          ? { left: el.offsetLeft, width: el.offsetWidth }
          : { top: el.offsetTop, height: el.offsetHeight }
      )
    }
    place()
    window.addEventListener('resize', place)
    return () => window.removeEventListener('resize', place)
  }, [box, active, axis])

  return style || { opacity: 0 }
}
