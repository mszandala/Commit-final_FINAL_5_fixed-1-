import { useEffect, useRef, useState } from 'react'
import { Gauge } from 'lucide-react'
import { endConversation, resetBudget, streamChat } from '../api'
import { refreshEvents } from '../events'
import { useMeta } from '../meta'
import { composeMessage, useAttachments } from './attachments'
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
  const attachments = useAttachments()
  // dragenter and dragleave fire for every child crossed, so the count says whether a file is over the chat.
  const [dragDepth, setDragDepth] = useState(0)

  const person = people.find((p) => p.id === roleId)
  const account = budgets[roleId]
  const { kind, share } = tightestLimit(account)

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [items, pending, failed])

  // A file dropped outside the chat would make the browser open it and leave the app.
  useEffect(() => {
    const stop = (e) => e.dataTransfer.types.includes('Files') && e.preventDefault()
    window.addEventListener('dragover', stop)
    window.addEventListener('drop', stop)
    return () => {
      window.removeEventListener('dragover', stop)
      window.removeEventListener('drop', stop)
    }
  }, [])

  function switchUser(next) {
    if (conversation.current) endConversation(conversation.current).catch(() => {})
    conversation.current = null
    setRoleId(next)
    setSessionStarted(false)
    setFailed(null)
  }

  // `resumed`: already retried in a new conversation after the backend forgot the old one.
  async function send(text, resumed = false) {
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
      // A restarted backend no longer knows the conversation: start a new session and send again.
      if (e.status === 404 && conversation.current && !resumed) {
        conversation.current = null
        setItems((prev) => {
          const at = prev.findLastIndex((item) => item.kind === 'user')
          const divider = { id: nextId++, kind: 'session', name: person.user, role: person.label }
          return [...prev.slice(0, at), divider, ...prev.slice(at)]
        })
        return await send(text, true)
      }
      // status 0: the request never got an answer.
      setFailed({ text, status: e.status ?? 0, detail: e.message })
    } finally {
      setPending(null)
      refreshEvents()
    }
  }

  // `files` are attachments already read to text; they go to the backend inside the message.
  function submit(text, files = []) {
    const added = [{ id: nextId++, kind: 'user', text, files: files.map(({ name }) => ({ name })) }]
    if (!sessionStarted) added.unshift({ id: nextId++, kind: 'session', name: person.user, role: person.label })
    setSessionStarted(true)
    setItems((prev) => [...prev, ...added])
    send(composeMessage(text, files))
  }

  const isFileDrag = (e) => e.dataTransfer.types.includes('Files')

  function drop(e) {
    if (!isFileDrag(e)) return
    e.preventDefault()
    setDragDepth(0)
    if (!pending) attachments.add(e.dataTransfer.files)
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
    <section
      className="flex h-full flex-col bg-white"
      onDragEnter={(e) => isFileDrag(e) && setDragDepth((n) => n + 1)}
      onDragLeave={(e) => isFileDrag(e) && setDragDepth((n) => Math.max(0, n - 1))}
      onDragOver={(e) => isFileDrag(e) && e.preventDefault()}
      onDrop={drop}
    >
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
        {failed && <ChatItem item={{ kind: 'error', ...failed }} onRetry={() => send(failed.text)} />}
      </div>

      <footer className="shrink-0 space-y-2.5 border-t border-line px-5 pt-3 pb-5">
        <Examples disabled={!!pending} onPick={(text) => submit(text)} />
        {share >= BUDGET_WARNING && (
          <p className={`flex items-center gap-1.5 text-[13px] ${share < 1 ? 'text-amber-text' : 'text-red-text'}`}>
            <Gauge size={14} />
            {BUDGET_NOTICE[kind](share)}
          </p>
        )}
        <Composer disabled={!!pending} onSend={submit} attachments={attachments} dragging={dragDepth > 0 && !pending} />
      </footer>
    </section>
  )
}
