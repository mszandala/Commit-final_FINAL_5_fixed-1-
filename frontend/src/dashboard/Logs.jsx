import { useLayoutEffect, useRef, useState } from 'react'
import { Search } from 'lucide-react'
import { getEvents } from '../mock/events'
import { formatNumber } from '../format'

const DECISIONS = ['All', 'Allowed', 'Redacted', 'Blocked']

// Left-edge bar and row tint mark the decision.
const BARS = {
  Allowed: 'shadow-[inset_4px_0_0_var(--color-green)]',
  Redacted: 'shadow-[inset_4px_0_0_var(--color-amber)]',
  Blocked: 'shadow-[inset_4px_0_0_var(--color-red)]',
}
const TINTS = {
  Allowed: 'bg-green/10 hover:bg-green/20',
  Redacted: 'bg-amber/10 hover:bg-amber/20',
  Blocked: 'bg-red/10 hover:bg-red/20',
}

const COLUMNS = [
  { label: 'Time' },
  { label: 'User' },
  { label: 'Role' },
  { label: 'Control' },
  { label: 'Reason' },
  { label: 'Tokens', numeric: true },
  { label: 'Latency', numeric: true },
]

const timeOf = (d) => d.toLocaleTimeString('en-GB')
const dateOf = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })

export default function Logs() {
  const [decision, setDecision] = useState('All')
  const [query, setQuery] = useState('')

  const scroller = useRef(null)

  const needle = query.trim().toLowerCase()
  const events = getEvents().filter(
    (e) =>
      (decision === 'All' || e.decision === decision) &&
      (!needle || `${e.user} ${e.control} ${e.reason}`.toLowerCase().includes(needle)),
  )

  // Newest events are at the bottom, so keep the view there.
  useLayoutEffect(() => {
    scroller.current.scrollTop = scroller.current.scrollHeight
  }, [decision, needle])

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-4 px-6 py-4">
        <div role="group" aria-label="Decision" className="flex gap-1">
          {DECISIONS.map((d) => (
            <button
              key={d}
              aria-pressed={decision === d}
              onClick={() => setDecision(d)}
              className={`rounded-md px-2.5 py-1 text-sm ${
                decision === d ? 'bg-blue-light text-ink' : 'text-grey hover:bg-white'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
        <label className="relative ml-auto block w-64">
          <Search size={16} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-grey" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search"
            aria-label="Search logs"
            className="w-full rounded-md border border-line bg-white py-1.5 pl-8 pr-2.5 text-sm outline-none focus:border-blue"
          />
        </label>
      </div>

      <div className="flex min-h-0 flex-1 flex-col px-6 pb-5">
        <div ref={scroller} className="min-h-0 overflow-auto rounded-md border border-line bg-white">
          <table className="w-full border-separate border-spacing-0 text-sm tabular-nums [&_tbody_tr:last-child_td]:border-b-0">
            <thead>
              <tr>
                {COLUMNS.map((c) => (
                  <th
                    key={c.label}
                    className={`sticky top-0 border-b border-line bg-white px-2.5 py-2 text-[13px] font-normal text-grey first:pl-4 last:pr-4 ${
                      c.numeric ? 'text-right' : 'text-left'
                    }`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className={TINTS[e.decision]}>
                  <td
                    className={`whitespace-nowrap border-b border-line px-2.5 py-1 pl-4 ${BARS[e.decision]}`}
                    title={e.time.toLocaleString('en-GB')}
                  >
                    <span className="mr-2 text-grey">{dateOf(e.time)}</span>
                    {timeOf(e.time)}
                  </td>
                  <td className="max-w-40 truncate border-b border-line px-2.5 py-1" title={e.user}>
                    {e.user}
                  </td>
                  <td className="max-w-24 truncate border-b border-line px-2.5 py-1 text-grey" title={e.role}>
                    {e.role}
                  </td>
                  <td className="max-w-40 truncate border-b border-line px-2.5 py-1" title={e.control}>
                    {e.control || <span className="text-grey">–</span>}
                  </td>
                  <td className="border-b border-line px-2.5 py-1 text-grey">
                    <div className="line-clamp-2 max-w-60" title={e.reason}>
                      {e.reason}
                    </div>
                  </td>
                  <td className="whitespace-nowrap border-b border-line px-2.5 py-1 text-right">{formatNumber(e.tokens)}</td>
                  <td className="whitespace-nowrap border-b border-line px-2.5 py-1 pr-4 text-right">{formatNumber(e.latency)} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
          {events.length === 0 && <p className="py-10 text-center text-grey">No matching events</p>}
        </div>
      </div>
    </div>
  )
}
