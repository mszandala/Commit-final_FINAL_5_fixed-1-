import { useEffect, useRef, useState } from 'react'
import { Gauge } from 'lucide-react'
import { endConversation, resetBudget, streamChat } from '../api'
import { refreshEvents } from '../events'
import { useMeta } from '../meta'
import ChatItem from './ChatItem'
import Composer from './Composer'
import Examples from './Examples'
import UserMenu from './UserMenu'
import { tightestLimit } from '../ui/BudgetBar'

const BUDGET_WARNING = 0.8

const BUDGET_NOTICE = {
  tokens: (share) => (share < 1 ? `${Math.round(share * 100)}% of today's budget used` : "Today's budget is used up"),
  spending: (share) => (share < 1 ? `${Math.round(share * 100)}% of the spending limit used` : 'Spending limit reached'),
}

let nextId = 1

// `people` is GET /roles: each role with its example user and budget (daily tokens, total spending).
export default function Chat({ people }) {
  const meta = useMeta()
  const [roleId, setRoleId] = useState('basic_user')
  const [items, setItems] = useState([])
  // Switching user starts a new session; the divider goes in with that session's first message.
  const [sessionStarted, setSessionStarted] = useState(false)
  const conversation = useRef(null)
  // Stage and tool calls of the request in flight.
  const [pending, setPending] = useState(null)
  const [failed, setFailed] = useState(null)
  const [budgets, setBudgets] = useState(() => Object.fromEntries(people.map((p) => [p.id, p.budget])))
  const listRef = useRef(null)

  const person = people.find((p) => p.id === roleId)
  const account = budgets[roleId]
  const { kind, share } = tightestLimit(account)

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [items, pending, failed])

  function switchUser(next) {
    if (conversation.current) endConversation(conversation.current).catch(() => {})
    conversation.current = null
    setRoleId(next)
    setSessionStarted(false)
    setFailed(null)
  }

  async function send(text) {
    setFailed(null)
    const tools = []
    setPending({ stage: '', tools })
    try {
      const result = await streamChat(
        { roleId, message: text, conversationId: conversation.current },
        (kind, data) => {
          if (kind === 'tool') tools.push(data)
          setPending((prev) => ({ stage: kind === 'stage' ? meta.stages[data.stage] : prev.stage, tools: [...tools] }))
        },
      )
      conversation.current = result.conversationId
      setBudgets((prev) => ({ ...prev, [roleId]: result.budget }))
      setItems((prev) => [...prev, { id: nextId++, kind: 'reply', ...result }])
    } catch (e) {
      // status 0: the request never got an answer.
      setFailed({ text, status: e.status ?? 0 })
    } finally {
      setPending(null)
      refreshEvents()
    }
  }

  function submit(text) {
    const added = [{ id: nextId++, kind: 'user', text }]
    if (!sessionStarted) added.unshift({ id: nextId++, kind: 'session', name: person.user, role: person.label })
    setSessionStarted(true)
    setItems((prev) => [...prev, ...added])
    send(text)
  }

  // Zeroes token and spending usage for one role, or for everyone when `id` is null.
  async function clearUsage(id) {
    try {
      const roles = await resetBudget(id)
      setBudgets(Object.fromEntries(roles.map((r) => [r.id, r.budget])))
    } catch {
      // The menu keeps showing the old figures; the next turn refreshes them.
    }
  }

  return (
    <section className="flex h-full flex-col bg-white">
      <header className="flex h-14 shrink-0 items-center border-b border-line px-5">
        <UserMenu
          people={people}
          roleId={roleId}
          account={account}
          disabled={!!pending}
          onSwitch={switchUser}
          onResetBudget={clearUsage}
        />
      </header>

      {/* `wrap-break-word` is inherited, so a long unbroken word wraps in every message instead of overflowing. */}
      <div ref={listRef} className="flex flex-1 flex-col gap-5 overflow-y-auto px-5 py-5 wrap-break-word">
        {items.map((item) => (
          <ChatItem key={item.id} item={item} />
        ))}
        {pending && <ChatItem item={{ kind: 'pending', ...pending }} />}
        {failed && <ChatItem item={{ kind: 'error', status: failed.status }} onRetry={() => send(failed.text)} />}
      </div>

      <footer className="shrink-0 space-y-2.5 border-t border-line px-5 pt-3 pb-5">
        <Examples disabled={!!pending} onPick={(text) => submit(text)} />
        {share >= BUDGET_WARNING && (
          <p className={`flex items-center gap-1.5 text-[13px] ${share < 1 ? 'text-amber-text' : 'text-red-text'}`}>
            <Gauge size={14} />
            {BUDGET_NOTICE[kind](share)}
          </p>
        )}
        <Composer disabled={!!pending} onSend={submit} />
      </footer>
    </section>
  )
}
