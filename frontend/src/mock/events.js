import { getConfig } from './config'
import { USERS } from './data'

const roleLabel = (id) => getConfig().roles.find((r) => r.id === id).label

const seed = (time, role, decision, control, reason, tokens, latency) => {
  const [h, m, s] = time.split(':').map(Number)
  const now = new Date()
  return {
    time: new Date(now.getFullYear(), now.getMonth(), now.getDate(), h, m, s),
    user: USERS[role].name,
    role: roleLabel(role),
    decision,
    control,
    reason,
    tokens,
    latency,
  }
}

// Oldest first, so the newest event sits at the bottom of the log.
let events = [
  seed('08:12:04', 'banker', 'Allowed', '', '', 2140, 1830),
  seed('08:31:47', 'basic_user', 'Allowed', '', '', 1320, 1210),
  seed('08:52:19', 'analyst', 'Blocked', 'Tool permissions', 'Tool read_client_records is not available for role Analyst', 1460, 1580),
  seed('09:05:33', 'hr', 'Allowed', '', '', 3860, 2410),
  seed('09:14:02', 'it', 'Redacted', 'PII policy', 'Masked: EMAIL', 1710, 1690),
  seed('09:40:58', 'basic_user', 'Allowed', 'Prompt guard', 'Flagged: The message tries to override the system instructions', 760, 1240),
  seed('10:02:11', 'portfolio_manager', 'Allowed', '', '', 5240, 3120),
  seed('10:17:45', 'lawyer', 'Blocked', 'Tool permissions', 'Tool read_stock_prices is not available for role Lawyer', 2980, 2240),
  seed('10:26:09', 'admin', 'Blocked', 'Code guard', "Import 'subprocess': runs processes", 2410, 1960),
  seed('10:48:30', 'banker', 'Redacted', 'PII policy', 'Masked: PHONE-NO', 1890, 1740),
  seed('11:03:52', 'hr', 'Blocked', 'PII policy', 'Reply contains always-blocked data: CREDIT-CARD-NO', 2650, 2050),
].map((e, i) => ({ id: i + 1, ...e }))

const listeners = new Set()

export function getEvents() {
  return events
}

export function subscribeEvents(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function addEvent(event) {
  events = [...events, { id: events.length + 1, time: new Date(), ...event }]
  listeners.forEach((listener) => listener())
}
