export function splitBuilds(pending, links) {
  const ids = new Set(links.map((link) => link.id))
  const cards = pending.filter((act) => !(act.link && ids.has(act.link)))
  const unsaved = new Set(cards.filter((act) => act.state === 'run' && act.name).map((act) => act.name))
  const saving = new Set(pending.filter((act) => act.state === 'run' && act.link).map((act) => act.link))
  const shown = links
    .filter((link) => !unsaved.has(link.name))
    .map((link) => (saving.has(link.id) ? { ...link, building: true } : link))
  return { cards, shown }
}
