// Readings of a logged turn shared by the dashboard and the report.

// A turn graded block by a failed model call is an error, not a block.
export const isBlocked = (e) => e.level === 'block' && e.decision !== 'Error'
export const isRefused = (e) => e.steps.some((s) => s.kind === 'refusal')
export const isHidden = (e) => e.hidden.length > 0

// Nearest-rank percentile: the smallest value at least `p`% of the values are at or below.
export const percentile = (values, p) => {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0
}

// Turns where each check flagged or blocked something, at that check's worst level in the turn,
// most triggered first.
export function controlCounts(events) {
  const controls = {}
  for (const e of events) {
    const worst = {}
    for (const s of e.steps) {
      if (s.level !== 'info' && s.kind !== 'error') worst[s.kind] = worst[s.kind] === 'block' ? 'block' : s.level
    }
    for (const [kind, level] of Object.entries(worst)) {
      const c = (controls[kind] ??= { kind, block: 0, warn: 0 })
      c[level]++
    }
  }
  return Object.values(controls).sort((a, b) => b.block + b.warn - (a.block + a.warn) || b.block - a.block)
}

// Dollars a turn spent on model calls: the chatbot's own, and the layer's checks.
export function turnCost(e) {
  let chat = 0
  let security = 0
  for (const s of e.steps) {
    if (s.kind !== 'model_call') continue
    if (s.details.purpose === 'chat') chat += s.details.cost ?? 0
    else security += s.details.cost ?? 0
  }
  return { chat, security }
}
