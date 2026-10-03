import { getEvents as fetchEvents } from './api'

// The audit log, refreshed on load and after each chat turn (the API has no push).
let events = []
const listeners = new Set()

// What the layer kept from the model or the user in a turn: PII types masked in the prompt, hidden
// or blocked in the reply, plus TOOL-RESULT when a tool's output was masked (those steps carry
// counts, not types).
function hiddenTypes(steps) {
  const types = steps.flatMap(({ kind, details: d }) => {
    if (kind === 'prompt_masking') return (d.decisions ?? []).filter((x) => x.decision !== 'send').map((x) => x.type)
    if (kind === 'output_filter') return [...(d.redacted ?? []), ...(d.blocked ?? [])]
    if (kind === 'tool_call' && Object.values(d.masked ?? {}).some(Boolean)) return ['TOOL-RESULT']
    return []
  })
  return [...new Set(types)]
}

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
    events = rows.map((e) => ({ ...e, time: new Date(e.time), hidden: hiddenTypes(e.steps) }))
    listeners.forEach((listener) => listener())
  } catch {
    // Keep the rows we have; the next turn tries again.
  }
}
