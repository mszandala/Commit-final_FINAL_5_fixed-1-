import { getEvents as fetchEvents } from './api'

// The audit log, refreshed on load and after each chat turn (the API has no push).
let events = []
const listeners = new Set()

export function getEvents() {
  return events
}

export function subscribeEvents(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export async function refreshEvents() {
  try {
    const rows = await fetchEvents()
    events = rows.map((e) => ({ ...e, time: new Date(e.time) }))
    listeners.forEach((listener) => listener())
  } catch {
    // Keep the rows we have; the next turn tries again.
  }
}
