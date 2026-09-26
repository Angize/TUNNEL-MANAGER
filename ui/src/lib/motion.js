import gsap from 'gsap'
import { CustomEase } from 'gsap/CustomEase'

gsap.registerPlugin(CustomEase)
CustomEase.create('ease-out', '0.23,1,0.32,1')
CustomEase.create('ease-in-out', '0.77,0,0.175,1')
CustomEase.create('ease-drawer', '0.32,0.72,0,1')

export const EASE_OUT = 'cubic-bezier(.23, 1, .32, 1)'
export const EASE_DRAWER = 'cubic-bezier(.32, .72, 0, 1)'

export function reducedMotion() {
  return matchMedia('(prefers-reduced-motion: reduce)').matches
}

export function narrow() {
  return matchMedia('(max-width: 640px)').matches
}

export { gsap }
