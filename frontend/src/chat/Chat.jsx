import { useEffect, useRef, useState } from 'react'
import { Gauge } from 'lucide-react'
import { USERS } from '../mock/data'
import { sendMessage } from '../mock/chat'
import ChatItem from './ChatItem'
import Composer from './Composer'
import Examples from './Examples'
import UserMenu from './UserMenu'

const BUDGET_WARNING = 0.8

let nextId = 1

export default function Chat({ config }) {
  const [roleId, setRoleId] = useState('basic_user')
  const [items, setItems] = useState([])
  // Switching user starts a new session; the divider goes in with that session's first message.
  const [sessionStarted, setSessionStarted] = useState(false)
  // Stage and tool calls of the request in flight.
  const [pending, setPending] = useState(null)
  const [failed, setFailed] = useState(null)
  // Tokens used today, per user; starts from the mock figures.
  const [usage, setUsage] = useState(() => Object.fromEntries(Object.entries(USERS).map(([id, u]) => [id, u.used])))
  const listRef = useRef(null)

  const user = USERS[roleId]
  const role = config.roles.find((r) => r.id === roleId)
  const account = { used: usage[roleId], limit: user.budget }
  const share = account.used / account.limit

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [items, pending, failed])

  function switchUser(next) {
    setRoleId(next)
    setSessionStarted(false)
    setFailed(null)
  }

  async function send(text, files) {
    setFailed(null)
    setPending({ stage: '', tools: [] })
    try {
      const result = await sendMessage({ text, files, user, used: usage[roleId], role, config }, setPending)
      setUsage((prev) => ({ ...prev, [roleId]: prev[roleId] + result.tokens }))
      setItems((prev) => [...prev, { id: nextId++, kind: 'reply', ...result }])
    } catch {
      setFailed({ text, files })
    } finally {
      setPending(null)
    }
  }

  function submit(text, files = []) {
    const attached = files.map(({ name, size }) => ({ name, size }))
    const added = [{ id: nextId++, kind: 'user', text, files: attached }]
    if (!sessionStarted) added.unshift({ id: nextId++, kind: 'session', name: user.name, role: role.label })
    setSessionStarted(true)
    setItems((prev) => [...prev, ...added])
    send(text, attached)
  }

  return (
    <section className="flex h-full flex-col bg-white">
      <header className="flex h-14 shrink-0 items-center border-b border-line px-5">
        <UserMenu roles={config.roles} roleId={roleId} account={account} disabled={!!pending} onSwitch={switchUser} />
      </header>

      <div ref={listRef} className="flex flex-1 flex-col gap-5 overflow-y-auto px-5 py-5">
        {items.map((item) => (
          <ChatItem key={item.id} item={item} />
        ))}
        {pending && <ChatItem item={{ kind: 'pending', ...pending }} />}
        {failed && <ChatItem item={{ kind: 'error' }} onRetry={() => send(failed.text, failed.files)} />}
      </div>

      <footer className="shrink-0 space-y-2.5 border-t border-line px-5 pt-3 pb-5">
        <Examples disabled={!!pending} onPick={(text) => submit(text)} />
        {share >= BUDGET_WARNING && (
          <p className={`flex items-center gap-1.5 text-[13px] ${share < 1 ? 'text-amber-text' : 'text-red-text'}`}>
            <Gauge size={14} />
            {share < 1 ? `${Math.round(share * 100)}% of today's budget used` : "Today's budget is used up"}
          </p>
        )}
        <Composer disabled={!!pending} onSend={submit} />
      </footer>
    </section>
  )
}
