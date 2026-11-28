function installOrbitalSky(backdrop) {
  const canvas = document.createElement('canvas')
  const moon = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  backdrop.append(canvas, moon)

  const ctx = canvas.getContext('2d')
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)')
  let width = 0
  let height = 0
  let pixelRatio = 0
  let stars = []
  let elapsed = 0
  let previous = null
  let frame = 0
  let route
  let pulse
  let starColor = getComputedStyle(backdrop).getPropertyValue('--star').trim()

  function starField(count) {
    let seed = 7285
    function random() {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0
      return seed / 4294967296
    }
    return Array.from({ length: count }, () => {
      const direction = random() * Math.PI * 2
      const speed = 5 + 13 * random()
      return {
        x: random(), y: random(),
        vx: Math.cos(direction) * speed, vy: Math.sin(direction) * speed,
        radius: .48 + 2.03 * Math.pow(random(), 2.1),
        alpha: .22 + .7 * random(), phase: random() * Math.PI * 2,
      }
    })
  }

  function lunarSurface() {
    const compact = width < 620
    const y0 = (compact ? 1.02 : 1.15) * height
    const y1 = (compact ? .795 : .79) * height
    const y2 = .715 * height
    const horizon = `M0 ${y0} Q${width * .5} ${y1} ${width} ${y2}`
    const outline = horizon + ` V${height + 2} H0Z`

    function rim(x) {
      const t = x / width
      return (1 - t) ** 2 * y0 + 2 * (1 - t) * t * y1 + t * t * y2
    }

    function crater(fraction, size, depth, angle) {
      const x = width * fraction
      const r = Math.min(width * size, height * .102)
      const y = rim(x) + depth * r
      return `<g transform="translate(${x} ${y}) rotate(${angle})">
        <ellipse rx="${r}" ry="${r * .65}" fill="url(#orbital-bowl)"/>
        <path d="M${-r} 0a${r} ${r * .65} 0 0 1 ${2 * r} 0" fill="none" stroke="var(--crater-3)" stroke-opacity=".62" stroke-width="1.5"/>
        <path d="M${r} 0a${r} ${r * .65} 0 0 1 ${-2 * r} 0" fill="none" stroke="var(--rim)" stroke-opacity=".46"/>
      </g>`
    }

    function pin(x) {
      const y = rim(x) + 4
      return `<g transform="translate(${x} ${y})">
        <ellipse rx="4.5" ry="1.45" fill="var(--pin)" opacity=".5"/>
        <path d="M0 0v-4" stroke="var(--pin)" stroke-width="1.1"/>
        <circle cy="-4" r="1.5" fill="var(--relay)"/>
      </g>`
    }

    const start = width * (compact ? .39 : .64)
    const end = width * (compact ? .625 : .78)
    const a = { x: start, y: rim(start) }
    const b = { x: end, y: rim(end) }
    const mid = { x: (start + end) / 2, y: (a.y + b.y) / 2 - Math.min(36, width * .047) }
    route = { a, b, mid }
    moon.setAttribute('viewBox', `0 0 ${width} ${height}`)
    moon.innerHTML = `<defs>
      <linearGradient id="orbital-soil" x1=".48" y1=".02" x2=".54" y2=".9">
        <stop stop-color="var(--soil-1)"/><stop offset=".27" stop-color="var(--soil-2)"/>
        <stop offset=".7" stop-color="var(--soil-3)"/><stop offset="1" stop-color="var(--soil-4)"/>
      </linearGradient>
      <radialGradient id="orbital-bowl" cx=".55" cy=".74" r=".88">
        <stop offset=".5" stop-color="var(--crater-1)"/><stop offset=".85" stop-color="var(--crater-2)"/><stop offset="1" stop-color="var(--crater-3)"/>
      </radialGradient>
      <filter id="orbital-atmosphere" x="-.1" y="-.6" width="1.2" height="2.2"><feGaussianBlur stdDeviation="7"/></filter>
      <clipPath id="orbital-surface"><path d="${outline}"/></clipPath>
    </defs>
    <path d="${horizon}" fill="none" stroke="var(--rim)" stroke-width="12" opacity=".4" filter="url(#orbital-atmosphere)"/>
    <path d="${outline}" fill="url(#orbital-soil)"/><path d="${horizon}" fill="none" stroke="var(--rim)" stroke-width="1.5"/>
    <g clip-path="url(#orbital-surface)">
      ${crater(compact ? .803 : .861, compact ? .119 : .073, 1.24, -21)}
      ${compact ? '' : crater(.971, .017, 2.35, -18)}
    </g>
    <path d="M${a.x} ${a.y} Q${mid.x} ${mid.y} ${b.x} ${b.y}" fill="none" stroke="var(--pin)" stroke-width="1" opacity=".6" stroke-dasharray="2 4"/>
    ${pin(start)}${pin(end)}<circle id="relayDot" r="1.8" fill="var(--relay)"/>`
    pulse = moon.querySelector('#relayDot')
  }

  function position(base, delta, span) {
    return ((base * span + delta) % span + span) % span
  }

  function paint() {
    if (!ctx || !width || !height) return
    ctx.clearRect(0, 0, width, height)
    ctx.fillStyle = starColor
    for (const star of stars) {
      const x = position(star.x, star.vx * elapsed, width + 8) - 4
      const y = position(star.y, star.vy * elapsed, height + 8) - 4
      ctx.globalAlpha = star.alpha * (.90 + .10 * Math.sin(star.phase + elapsed * .63))
      ctx.beginPath()
      ctx.arc(x, y, star.radius, 0, Math.PI * 2)
      ctx.fill()
    }
    ctx.globalAlpha = 1
    const t = (elapsed / 8.5 + .27) % 1
    const u = 1 - t
    const { a, mid, b } = route
    pulse.setAttribute('cx', u * u * a.x + 2 * u * t * mid.x + t * t * b.x)
    pulse.setAttribute('cy', u * u * a.y + 2 * u * t * mid.y + t * t * b.y)
    pulse.setAttribute('opacity', Math.min(.88, t * 8, (1 - t) * 8))
  }

  function tick(now) {
    frame = requestAnimationFrame(tick)
    if (previous === null) previous = now
    const delta = now - previous
    if (delta < 1000 / 32) return
    elapsed += Math.min(delta, 120) / 1000
    previous = now
    paint()
  }

  function updatePlayback() {
    cancelAnimationFrame(frame)
    previous = null
    if (ctx && width && height && !preference.matches && !document.hidden) frame = requestAnimationFrame(tick)
  }

  function resize() {
    const nextWidth = backdrop.clientWidth
    const nextHeight = backdrop.clientHeight
    const ratio = Math.min(2, window.devicePixelRatio || 1)
    if (nextWidth === width && nextHeight === height && ratio === pixelRatio) return
    width = nextWidth
    height = nextHeight
    pixelRatio = ratio
    if (width && height) {
      canvas.width = Math.round(width * ratio)
      canvas.height = Math.round(height * ratio)
      if (ctx) ctx.setTransform(ratio, 0, 0, ratio, 0, 0)
      stars = starField(Math.max(28, Math.min(140, Math.round(width * height / 7200))))
      lunarSurface()
      paint()
    }
    updatePlayback()
  }

  resize()
  new ResizeObserver(resize).observe(backdrop)
  new MutationObserver(() => {
    starColor = getComputedStyle(backdrop).getPropertyValue('--star').trim()
    paint()
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  preference.addEventListener('change', updatePlayback)
  document.addEventListener('visibilitychange', updatePlayback)
}

installOrbitalSky(document.querySelector('.orbital-sky'))
