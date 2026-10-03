import { Fragment, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { ChevronRight, Download, MessageSquare } from 'lucide-react'
import { EXPORT_URL } from '../api'
import { getEvents, subscribeEvents } from '../events'
import { formatNumber } from '../format'
import { useMeta } from '../meta'
import Comments from './Comments'
import SearchBox from './SearchBox'
import { advancedMatcher, plainMatcher } from './search'

// The backend grades every turn and every step: info (nothing to report), warn (flagged or
// data hidden) and block. A turn takes the highest level among its steps.
const RANK = { info: 0, warn: 1, block: 2 }
const LEVELS = [
  { id: 'info', label: 'All' },
  { id: 'warn', label: 'Warnings and blocks' },
  { id: 'block', label: 'Blocks only' },
]
const LEVEL_NAMES = { info: 'OK', warn: 'Warning', block: 'Blocked' }

// Left-edge bar marks the level; the row tints on hover. Screen readers and tooltips get it as text.
const BARS = {
  info: 'shadow-[inset_4px_0_0_var(--color-green)]',
  warn: 'shadow-[inset_4px_0_0_var(--color-amber)]',
  block: 'shadow-[inset_4px_0_0_var(--color-red)]',
}
const TINTS = {
  info: 'hover:bg-green/10',
  warn: 'hover:bg-amber/10',
  block: 'hover:bg-red/10',
}
const DOTS = { info: 'bg-green', warn: 'bg-amber', block: 'bg-red' }
const STEP_TEXT = { info: 'text-grey', warn: 'text-amber-text', block: 'text-red-text' }
const ZONE_TAGS = {
  security: 'bg-violet/20',
  chatbot: 'bg-blue-light/60',
  local: 'bg-teal/25',
}

const COLUMNS = [
  { label: '' },
  { label: 'Time' },
  { label: 'User' },
  { label: 'Role' },
  { label: 'Control' },
  { label: 'Reason' },
  { label: 'Steps', numeric: true },
  { label: 'Tokens', numeric: true },
  { label: 'Latency', numeric: true },
]

const timeOf = (d) => d.toLocaleTimeString('en-GB')
const dateOf = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })

function Select({ label, value, onChange, options }) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="shrink-0 rounded-md border border-line bg-white px-2 py-1.5 text-sm outline-none focus:border-blue"
    >
      <option value="all">{label}: all</option>
      {Object.entries(options).map(([id, name]) => (
        <option key={id} value={id}>
          {name}
        </option>
      ))}
    </select>
  )
}

// `found`: the search matched this step and not all of its turn's steps.
function Step({ step, zones, found }) {
  return (
    <details className="group">
      <summary
        className={`flex cursor-pointer list-none items-baseline gap-2 rounded-sm py-1 pl-3 pr-2 [&::-webkit-details-marker]:hidden ${BARS[step.level]} ${
          found ? 'bg-blue-light/40' : TINTS[step.level]
        }`}
        title={LEVEL_NAMES[step.level]}
      >
        <ChevronRight size={14} className="shrink-0 self-center text-grey transition-transform group-open:rotate-90" />
        <span className="sr-only">{LEVEL_NAMES[step.level]}: </span>
        <span className="w-32 shrink-0 text-ink">{step.label}</span>
        <span className={`w-24 shrink-0 rounded-sm px-1.5 py-px text-center text-xs text-ink ${ZONE_TAGS[step.zone] ?? 'bg-page'}`}>
          {zones[step.zone] ?? step.zone}
        </span>
        <span className={`min-w-0 flex-1 break-words ${STEP_TEXT[step.level]}`}>{step.summary}</span>
        <span className="shrink-0 text-grey">{formatNumber(step.durationMs)} ms</span>
      </summary>
      <pre className="mb-1.5 ml-3 mt-1 whitespace-pre-wrap break-words rounded-md bg-page px-3 py-2 font-mono text-[12.5px] leading-relaxed text-ink">
        {JSON.stringify(step.details, null, 2)}
      </pre>
    </details>
  )
}

// `initial` opens the log on a query or filters, when the dashboard sends someone here.
export default function Logs({ initial = {} }) {
  const meta = useMeta()
  const [level, setLevel] = useState(initial.level ?? 'info')
  const [kind, setKind] = useState(initial.kind ?? 'all')
  const [zone, setZone] = useState('all')
  // Each mode keeps its own query, so switching away and back finds the old one still there.
  const [queries, setQueries] = useState({ plain: '', advanced: initial.query ?? '' })
  const [advanced, setAdvanced] = useState(initial.query !== undefined)
  const mode = advanced ? 'advanced' : 'plain'
  const query = queries[mode]
  const setQuery = (value) => setQueries({ ...queries, [mode]: value })
  // Turns opened or closed by hand; the rest follow `expandAll`.
  const [toggled, setToggled] = useState({})
  const [expandAll, setExpandAll] = useState(false)

  const scroller = useRef(null)

  const all = useSyncExternalStore(subscribeEvents, getEvents)

  // While an advanced query is half typed or wrong, the table keeps the last results that worked
  // in this mode, or shows everything right after a switch.
  const result = useMemo(
    () => (advanced ? advancedMatcher(query, meta) : plainMatcher(query, meta)),
    [advanced, query, meta],
  )
  const everything = useMemo(() => plainMatcher('', meta), [meta])
  const [kept, setKept] = useState({ advanced, result })
  if (!result.error && result !== kept.result) setKept({ advanced, result })
  const search = kept.advanced === advanced ? kept.result : everything

  // Turns where the search found some steps but not all open on them, with those steps marked.
  // An empty query finds every step, so nothing is marked.
  const found = useMemo(() => {
    const map = new Map()
    for (const e of all) {
      const hits = e.steps.filter((s) => search.matchStep(e, s))
      if (hits.length && hits.length < e.steps.length) map.set(e.id, new Set(hits))
    }
    return map
  }, [all, search])

  // With a step type or zone chosen, a turn is listed when one of its steps matches, and only
  // those steps are shown under it.
  const narrowed = kind !== 'all' || zone !== 'all'
  const stepMatches = (s) =>
    RANK[s.level] >= RANK[level] && (kind === 'all' || s.kind === kind) && (zone === 'all' || s.zone === zone)
  // The API sends the oldest first; the log shows the newest on top.
  const events = all
    .filter((e) => search.match(e) && (narrowed ? e.steps.some(stepMatches) : RANK[e.level] >= RANK[level]))
    .reverse()
  const isOpen = (e) => toggled[e.id] ?? (expandAll || narrowed || found.has(e.id))

  // Keep the view on the newest events when the log or the filters change.
  useLayoutEffect(() => {
    scroller.current.scrollTop = 0
  }, [level, kind, zone, search, all])

  return (
    <div className="flex h-full flex-col">
      {/* Advanced search takes the whole first row and pushes the filters below it. Plain search
          moves to its own row only when the window is too narrow for it. */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-3 px-6 py-4">
        <div role="group" aria-label="Level" className="flex shrink-0 gap-1">
          {LEVELS.map((l) => (
            <button
              key={l.id}
              aria-pressed={level === l.id}
              onClick={() => setLevel(l.id)}
              className={`whitespace-nowrap rounded-md px-2.5 py-1 text-sm ${
                level === l.id ? 'bg-blue-light text-ink' : 'text-grey hover:bg-white'
              }`}
            >
              {l.label}
            </button>
          ))}
        </div>
        <Select label="Step" value={kind} onChange={setKind} options={meta.stepKinds} />
        <Select label="Zone" value={zone} onChange={setZone} options={meta.zones} />
        <button
          aria-pressed={expandAll}
          onClick={() => {
            setExpandAll(!expandAll)
            setToggled({})
          }}
          className={`shrink-0 whitespace-nowrap rounded-md px-2.5 py-1 text-sm ${expandAll ? 'bg-blue-light text-ink' : 'text-grey hover:bg-white'}`}
        >
          {expandAll ? 'Collapse all' : 'Expand all'}
        </button>
        <a
          href={EXPORT_URL}
          download="conversations.json"
          title="Download all saved conversations with steps and comments"
          className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1 text-sm text-grey hover:bg-white hover:text-ink"
        >
          <Download size={14} />
          Export
        </a>
        <SearchBox
          value={query}
          onChange={setQuery}
          advanced={advanced}
          onToggle={() => setAdvanced(!advanced)}
          error={result.error}
        />
      </div>

      <div className="flex min-h-0 flex-1 flex-col px-6 pb-5">
        {/* `relative` keeps the absolutely placed sr-only labels inside the scroller; without it they
            stretch the page once rows are open. */}
        <div ref={scroller} className="relative min-h-0 overflow-auto rounded-md border border-line bg-white">
          <table className="w-full border-separate border-spacing-0 text-sm tabular-nums [&_tbody_tr:last-child_td]:border-b-0">
            <thead>
              <tr>
                {COLUMNS.map((c, i) => (
                  <th
                    key={i}
                    className={`sticky top-0 z-10 border-b border-line bg-white px-2.5 py-2 text-[13px] font-normal text-grey first:pl-4 last:pr-4 ${
                      c.numeric ? 'text-right' : 'text-left'
                    }`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e) => {
                const open = isOpen(e)
                const steps = narrowed || level !== 'info' ? e.steps.filter(stepMatches) : e.steps
                return (
                  <Fragment key={e.id}>
                    <tr
                      className={`cursor-pointer ${TINTS[e.level]}`}
                      onClick={() => setToggled({ ...toggled, [e.id]: !open })}
                    >
                      <td className={`border-b border-line py-1 pl-4 pr-0 ${BARS[e.level]}`}>
                        <button
                          aria-expanded={open}
                          aria-label={`${open ? 'Hide' : 'Show'} steps of turn ${e.id}`}
                          className="grid place-items-center text-grey"
                        >
                          <ChevronRight size={14} className={`transition-transform ${open ? 'rotate-90' : ''}`} />
                        </button>
                      </td>
                      <td
                        className="whitespace-nowrap border-b border-line px-2.5 py-1"
                        title={`${LEVEL_NAMES[e.level]} (${e.decision}), ${e.time.toLocaleString('en-GB')}`}
                      >
                        <span className="sr-only">{LEVEL_NAMES[e.level]}, </span>
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
                        {e.control || <span className="text-grey">&ndash;</span>}
                      </td>
                      <td className="border-b border-line px-2.5 py-1 text-grey">
                        <div className="line-clamp-2 max-w-60" title={e.reason}>
                          {e.reason}
                        </div>
                      </td>
                      <td className="whitespace-nowrap border-b border-line px-2.5 py-1 text-right">
                        <span className="inline-flex items-center gap-1.5">
                          {['block', 'warn'].map(
                            (l) =>
                              e.steps.some((s) => s.level === l) && (
                                <span key={l} className={`size-1.5 rounded-full ${DOTS[l]}`} title={LEVEL_NAMES[l]} />
                              ),
                          )}
                          {e.stepCount}
                          {e.commentCount > 0 && (
                            <span className="ml-1.5 inline-flex items-center gap-0.5 text-grey" title="Comments on this conversation">
                              <MessageSquare size={12} />
                              {e.commentCount}
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="whitespace-nowrap border-b border-line px-2.5 py-1 text-right">{formatNumber(e.tokens)}</td>
                      <td className="whitespace-nowrap border-b border-line px-2.5 py-1 pr-4 text-right">{formatNumber(e.latencyMs)} ms</td>
                    </tr>
                    {open && (
                      <tr>
                        <td colSpan={COLUMNS.length} className="border-b border-line bg-page/60 py-2 pl-9 pr-4">
                          {e.maskedPrompt && (
                            <p className="mb-1.5 pl-3 text-[13px] text-grey">
                              Sent to the model:<span className="ml-1.5 font-mono text-[12.5px] text-ink">{e.maskedPrompt}</span>
                            </p>
                          )}
                          <div className="space-y-px text-[13px]">
                            {steps.map((s) => (
                              <Step key={s.index} step={s} zones={meta.zones} found={found.get(e.id)?.has(s)} />
                            ))}
                          </div>
                          {steps.length < e.steps.length && (
                            <p className="mt-1.5 pl-3 text-[13px] text-grey">
                              {steps.length} of {e.steps.length} steps match the filters
                            </p>
                          )}
                          <Comments conversationId={e.conversationId} eventId={e.id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {events.length === 0 && <p className="py-10 text-center text-grey">No matching events</p>}
        </div>
      </div>
    </div>
  )
}
