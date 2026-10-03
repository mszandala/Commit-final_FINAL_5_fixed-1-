// Backend API v1 (backend/API.md). Vite proxies /api to the backend in development.
const BASE = import.meta.env.VITE_API_URL ?? '/api/v1'

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === 'string' ? detail : `HTTP ${status}`)
    this.status = status
  }
}

async function request(path, { method = 'GET', body } = {}) {
  const response = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new ApiError(response.status, error.detail)
  }
  return response.status === 204 ? null : response.json()
}

export const getMeta = () => request('/meta')
export const getRoles = () => request('/roles')
export const resetBudget = (roleId) =>
  request(`/budget/reset${roleId ? `?roleId=${encodeURIComponent(roleId)}` : ''}`, { method: 'POST' })
export const getConfig = () => request('/config')
export const getConfigDefaults = () => request('/config/defaults')
export const updateConfig = (update) => request('/config', { method: 'PUT', body: update })
export const getEvents = () => request('/events?steps=true')
export const endConversation = (id) => request(`/conversations/${id}`, { method: 'DELETE' })

// One chat turn over SSE. `onEvent(kind, data)` gets each stage and tool event;
// resolves with the final ChatResponse, rejects with ApiError on an error event.
export async function streamChat({ roleId, message, conversationId }, onEvent) {
  const response = await fetch(`${BASE}/chat/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ roleId, message, conversationId }),
  })
  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new ApiError(response.status, error.detail)
  }

  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += value
    let end
    while ((end = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, end)
      buffer = buffer.slice(end + 2)
      const kind = block.match(/^event: (.*)$/m)?.[1]
      const data = JSON.parse(block.match(/^data: (.*)$/m)?.[1] ?? 'null')
      if (kind === 'result') return data
      if (kind === 'error') throw new ApiError(data.status, data.detail)
      onEvent(kind, data)
    }
  }
  throw new ApiError(0, 'The stream ended without a result')
}
