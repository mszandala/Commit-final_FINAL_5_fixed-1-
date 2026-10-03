const TEXT = 'Sample text'

const sample = (id, decision, seconds) => ({
  id,
  time: new Date(2026, 0, 1, 0, 0, seconds),
  user: TEXT,
  role: TEXT,
  decision,
  control: decision === 'Allowed' ? '' : TEXT,
  reason: decision === 'Allowed' ? '' : TEXT,
  tokens: decision === 'Blocked' ? 0 : 2137,
  latency: decision === 'Blocked' ? 0 : 67,
})

// Oldest first, so the newest event sits at the bottom of the log.
const events = ['Allowed', 'Blocked', 'Allowed', 'Redacted', 'Blocked', 'Redacted'].map((decision, i) =>
  sample(i + 1, decision, i < 3 ? 0 : 1),
)

export function getEvents() {
  return events
}
