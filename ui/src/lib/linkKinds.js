export const LINK_KIND_IDS = ['tunnels', 'core', 'portfw']

export function isLinkKind(id) {
  return LINK_KIND_IDS.includes(id)
}
