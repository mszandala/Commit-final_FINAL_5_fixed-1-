import { useEffect, useRef, useState } from 'react'
import { CloudOff, Gauge, RotateCw } from 'lucide-react'
import { ROLES } from '../mock/data'
import { sendMessage } from '../mock/chat'
import { formatNumber } from '../format'
import Button from '../ui/Button'
import Notice from '../ui/Notice'
import ChatItem from './ChatItem'
import Composer from './Composer'
import Pending from './Pending'
import UserMenu from './UserMenu'

const BUDGET_WARNING = 0.8

let nextId = 1

export default function Chat() {
  const [role, setRole] = useState('employee')
  const [items, setItems] = useState([])
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(null)
  const listRef = useRef(null)

  const account = { used: ROLES[role].used, limit: ROLES[role].budget }
  const share = account.used / account.limit

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [items, pending, failed])

  function switchRole(next) {
    setRole(next)
    setItems([])
    setFailed(null)
  }

  async function send(text) {
    setFailed(null)
    setPending(true)
    try {
      const result = await sendMessage(text)
      setItems((prev) => [...prev, { id: nextId++, kind: 'reply', ...result }])
    } catch {
      setFailed(text)
    } finally {
      setPending(false)
    }
  }

  function submit(text, files = []) {
    const attached = files.map(({ name, size }) => ({ name, size }))
    setItems((prev) => [...prev, { id: nextId++, kind: 'user', text, files: attached }])
    send(text)
  }

  return (
    <section className="flex h-full flex-col bg-white">
      <header className="flex h-14 shrink-0 items-center border-b border-line px-5">
        <UserMenu role={role} account={account} disabled={pending} onSwitch={switchRole} />
      </header>

      <div ref={listRef} className="flex flex-1 flex-col gap-5 overflow-y-auto px-5 py-5">
        {items.map((item) => (
          <ChatItem key={item.id} item={item} />
        ))}
        {pending && <Pending />}
        {failed && (
          <Notice icon={CloudOff} title="Cannot reach the server">
            <Button size="sm" icon={RotateCw} onClick={() => send(failed)} className="mt-2">
              Retry
            </Button>
          </Notice>
        )}
      </div>

      <footer className="shrink-0 space-y-2.5 px-5 pb-5">
        {share >= BUDGET_WARNING && share < 1 && (
          <p className="flex items-center gap-1.5 text-[13px] text-amber-text">
            <Gauge size={14} />
            {Math.round(share * 100)}% of today's budget used, {formatNumber(account.limit - account.used)} tokens
            left
          </p>
        )}
        <Composer disabled={pending} onSend={submit} />
      </footer>
    </section>
  )
}
