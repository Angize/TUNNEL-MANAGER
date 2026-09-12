import { useEffect, useState } from 'react'
import { draggingId, subscribeReorder } from './reorder.js'

export default function useDragging(id) {
  const [on, setOn] = useState(() => draggingId() === id)

  useEffect(() => subscribeReorder((state) => setOn(state.draggingId === id)), [id])

  return on
}
