import { useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { getEvents, subscribeEvents } from '../events'
import { formatNumber, formatUsd } from '../format'
import { useMeta } from '../meta'
import { controlCounts, isBlocked, isHidden, isRefused, percentile } from './turns'

// Answers "are we safe and what does it cost?" from the events the log already holds. Controls,
// turns and users open the log on the turns behind them.

// Model calls by who made them: the chatbot, or the layer's own checks. Colours follow the
// purpose, so a missing one never repaints the others.
const PURPOSES = {
  chat: { label: 'Chatbot', color: 'bg-navy' },
  company_policy_classifier: { label: 'Policy classifier', color: 'bg-blue' },
  pii_judge: { label: 'PII judge', color: 'bg-teal' },
}
const OTHER_PURPOSE = { color: 'bg-grey' }
const LOCAL_CHECKS = {
  label: 'Local checks',
  color: 'bg-violet',
  hint: 'Prompt guard, prompt masking, reply filter and refusal detection, run on our server',
}

// Where a turn's time goes. The backend records a step when it finishes and `durationMs` is the
// time since the step before, so a model call's duration is the call itself and the decision
// logged right after it takes about 0 ms. Tools and a failed call count as the chatbot's time.
const timeGroup = (s) =>
  s.kind === 'model_call'
    ? s.details.purpose
    : s.kind === 'tool_call' || s.kind === 'error'
      ? 'chat'
      : s.kind === 'company_policy'
        ? 'company_policy_classifier'
        : s.kind === 'pii_judge'
          ? 'pii_judge'
          : 'local'
const RECENT_TURNS = 10

// Spacing in px, [loosest, normal, tightest]. The page loosens or squeezes between them to end on
// the line of the chat's message box (the same 20px from the bottom).
const SPACING = {
  '--top': [28, 20, 8],
  '--gap': [20, 12, 6],
  '--pad': [24, 16, 10],
  '--head': [16, 12, 6],
  '--share': [18, 12, 6],
  '--cell': [10, 6, 2],
  '--bar': [8, 4, 1],
}

// `squeeze` runs from -1 (loosest) through 0 (normal) to 1 (tightest).
const spacingAt = (squeeze) =>
  Object.fromEntries(
    Object.entries(SPACING).map(([name, [loosest, normal, tightest]]) => [
      name,
      `${squeeze < 0 ? normal + (normal - loosest) * squeeze : normal - (normal - tightest) * squeeze}px`,
    ]),
  )

// How far to squeeze. It measures the content at normal spacing, then at whichever end it needs:
// when even the tightest overflows it keeps the normal spacing and lets the page scroll, and when
// even the loosest leaves room it stays loosest. Otherwise it homes in on the amount that leaves
// under a pixel spare, guessing along the line between the closest tries on either side (the
// height is only roughly straight, as a row is as tall as its tallest panel). Remeasures when the
// pane resizes or the log changes; the tries run before paint, so nothing flickers.
const MAX_TRIES = 6

function useSqueeze(scroller, content, events) {
  const [size, setSize] = useState('')
  const [fit, setFit] = useState({ squeeze: 0, tries: [] })
  if (fit.size !== size || fit.events !== events) setFit({ size, events, squeeze: 0, tries: [] })

  useEffect(() => {
    const observer = new ResizeObserver(([entry]) => setSize(`${entry.contentRect.width}x${entry.contentRect.height}`))
    observer.observe(scroller.current)
    return () => observer.disconnect()
  }, [scroller])

  useLayoutEffect(() => {
    if (fit.done) return
    const over = content.current.getBoundingClientRect().height - scroller.current.clientHeight
    const tries = [...fit.tries, [fit.squeeze, over]]
    const settle = (squeeze) => setFit({ ...fit, squeeze, done: true })
    if (over <= 0 && over > -1) return settle(fit.squeeze)
    if (tries.length === 1) return setFit({ ...fit, tries, squeeze: over > 0 ? 1 : -1 })
    // Still on the same side of the line at the far end: scroll at normal spacing, or stay loosest.
    if (tries.length === 2 && Math.sign(over) === Math.sign(tries[0][1])) return settle(over > 0 ? 0 : -1)
    // The most squeeze that still overflows, and the least that fits.
    const [s1, o1] = tries.filter(([, o]) => o > 0).reduce((a, b) => (b[0] > a[0] ? b : a))
    const [s2, o2] = tries.filter(([, o]) => o <= 0).reduce((a, b) => (b[0] < a[0] ? b : a))
    if (tries.length >= MAX_TRIES) return settle(s2)
    setFit({ ...fit, tries, squeeze: s1 + ((o1 + 0.5) / (o1 - o2)) * (s2 - s1) })
  }, [fit, scroller, content])

  return fit.squeeze
}

const LEVEL_BARS = { block: 'bg-red', warn: 'bg-amber' }
const LEVEL_NAMES = { block: 'Blocked', warn: 'Warning' }

const percent = (part, whole) => (whole ? `${Math.round((part / whole) * 100)}%` : '0%')

function summarize(events) {
  const purposes = {}
  const users = {}
  const time = {}
  const turns = []
  for (const e of events) {
    // Consecutive steps of one group become one segment of the turn's bar.
    const parts = []
    const spent = {}
    for (const s of e.steps) {
      const group = timeGroup(s)
      spent[group] = (spent[group] ?? 0) + s.durationMs
      if (s.durationMs > 0) {
        if (parts.at(-1)?.group === group) parts.at(-1).ms += s.durationMs
        else parts.push({ group, ms: s.durationMs })
      }
      if (s.kind === 'model_call') {
        const p = (purposes[s.details.purpose] ??= { calls: 0, tokens: 0, cost: 0 })
        p.calls++
        p.tokens += s.details.tokens ?? 0
        p.cost += s.details.cost ?? 0
      }
    }
    for (const [group, ms] of Object.entries(spent)) {
      const t = (time[group] ??= { id: group, total: 0, samples: [] })
      t.total += ms
      t.samples.push(ms)
    }
    turns.push({ id: e.id, time: e.time, latencyMs: e.latencyMs, parts })
    const u = (users[e.user] ??= { user: e.user, role: e.role, turns: 0, blocked: 0, hidden: 0, refused: 0 })
    u.turns++
    u.blocked += isBlocked(e)
    u.hidden += isHidden(e)
    u.refused += isRefused(e)
  }
  // The chatbot first, then the layer's parts by how much they take.
  const chatFirst = (key) => (a, b) => (a.id === 'chat' ? -1 : b.id === 'chat' ? 1 : b[key] - a[key])
  // Percentiles of a part count only the turns it ran in: a PII judge that runs in one turn of
  // ten has a p50 of its own time, not 0.
  const spread = (samples) => ({
    p50: percentile(samples, 50),
    p95: percentile(samples, 95),
    slowest: Math.max(0, ...samples),
  })
  return {
    controls: controlCounts(events),
    purposes: Object.entries(purposes)
      .map(([id, p]) => ({ id, ...p }))
      .sort(chatFirst('cost')),
    time: Object.values(time)
      .filter((t) => t.total > 0)
      .map(({ samples, ...t }) => ({ ...t, ...spread(samples) }))
      .sort(chatFirst('total')),
    turnTime: spread(events.map((e) => e.latencyMs)),
    turns: turns.slice(-RECENT_TURNS).reverse(),
    users: Object.values(users).sort(
      (a, b) => b.blocked + b.refused - (a.blocked + a.refused) || b.hidden - a.hidden || b.turns - a.turns,
    ),
  }
}

function Panel({ title, aside, wide, children }) {
  return (
    <section className={`rounded-md border border-line bg-white px-4 py-(--pad) ${wide ? 'col-span-full' : ''}`}>
      {title && (
        <div className="mb-(--head) flex items-baseline justify-between gap-4">
          <h2 className="font-semibold text-navy">{title}</h2>
          {aside}
        </div>
      )}
      {children}
    </section>
  )
}

const Empty = ({ children }) => <p className="py-4 text-sm text-grey">{children}</p>

const Count = ({ n }) => (n ? formatNumber(n) : <span className="text-grey">&ndash;</span>)

// One horizontal bar per row, scaled to the largest row; segments sit side by side with a 2px gap.
function BarRow({ label, segments, max, title, onClick }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0)
  return (
    <button
      onClick={onClick}
      title={title}
      className="grid w-full grid-cols-[9rem_1fr_2.5rem] items-center gap-3 rounded-sm px-1.5 py-(--bar) text-left text-sm hover:bg-blue-light/30"
    >
      <span className="truncate">{label}</span>
      <span className="flex h-2.5 gap-0.5" style={{ width: `${(total / max) * 100}%` }}>
        {segments.map(
          (s, i) =>
            s.value > 0 && (
              <span key={i} className={`h-full last:rounded-r-sm ${s.color}`} style={{ flexGrow: s.value }} />
            ),
        )}
      </span>
      <span className="text-right tabular-nums">{formatNumber(total)}</span>
    </button>
  )
}

const Legend = ({ items }) => (
  <span className="flex gap-3 text-[13px] text-grey">
    {items.map(([label, color]) => (
      <span key={label} className="inline-flex items-center gap-1.5">
        <span className={`size-2 rounded-full ${color}`} />
        {label}
      </span>
    ))}
  </span>
)

// Parts of a whole on one bar, 2px apart.
function ShareBar({ parts }) {
  const total = parts.reduce((sum, p) => sum + p.value, 0)
  return (
    <div className="my-(--share) flex h-2.5 gap-0.5">
      {parts.map(
        (p) =>
          p.value > 0 && (
            <span
              key={p.id}
              title={p.title}
              className={`h-full first:rounded-l-sm last:rounded-r-sm ${p.color}`}
              style={{ flexGrow: p.value / total }}
            />
          ),
      )}
    </div>
  )
}

const timeOf = (d) => d.toLocaleTimeString('en-GB')

const TH = 'whitespace-nowrap border-b border-line px-1.5 pb-(--cell) text-[13px] font-normal text-grey'
const TD = 'border-b border-line px-1.5 py-(--cell)'
const NUM = `${TD} whitespace-nowrap text-right`

export default function Overview({ onOpenLogs }) {
  const meta = useMeta()
  const events = useSyncExternalStore(subscribeEvents, getEvents)
  const stats = useMemo(() => summarize(events), [events])
  const scroller = useRef(null)
  const content = useRef(null)
  const squeeze = useSqueeze(scroller, content, events)
  const spacing = spacingAt(squeeze)

  const controlMax = Math.max(...stats.controls.map((c) => c.block + c.warn))
  const spend = stats.purposes.reduce((sum, p) => sum + p.cost, 0)
  const securitySpend = stats.purposes.filter((p) => p.id !== 'chat').reduce((sum, p) => sum + p.cost, 0)
  const purpose = (id) => PURPOSES[id] ?? { ...OTHER_PURPOSE, label: id }
  const group = (id) => (id === 'local' ? LOCAL_CHECKS : purpose(id))
  const allTime = stats.time.reduce((sum, t) => sum + t.total, 0)
  const securityTime = stats.time.filter((t) => t.id !== 'chat').reduce((sum, t) => sum + t.total, 0)
  const slowestTurn = Math.max(1, ...stats.turns.map((t) => t.latencyMs))

  return (
    <div ref={scroller} className="h-full overflow-auto">
      <div ref={content} style={spacing} className="px-6 pb-5 pt-(--top)">
        {events.length === 0 ? (
          <p className="py-10 text-center text-grey">No turns yet</p>
        ) : (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(max(22rem,calc((100%-var(--gap))/2)),1fr))] gap-(--gap)">
            {/* Two columns, or one when two would be under 22rem each; never a third, which the
                full-width panels would hold open as an empty slot beside the first row. */}
            <Panel
              title="Most triggered controls"
              aside={
                <Legend
                  items={[
                    [LEVEL_NAMES.block, LEVEL_BARS.block],
                    [LEVEL_NAMES.warn, LEVEL_BARS.warn],
                  ]}
                />
              }
            >
              {stats.controls.length ? (
                stats.controls.map((c) => (
                  <BarRow
                    key={c.kind}
                    label={meta.stepKinds[c.kind] ?? c.kind}
                    segments={['block', 'warn'].map((l) => ({ value: c[l], color: LEVEL_BARS[l] }))}
                    max={controlMax}
                    title={`${c.block} blocked, ${c.warn} with a warning`}
                    onClick={() => onOpenLogs({ level: 'warn', kind: c.kind })}
                  />
                ))
              ) : (
                <Empty>No control has fired yet</Empty>
              )}
            </Panel>

            <Panel title="Security layer cost">
              {stats.purposes.length ? (
                <>
                  <p className="flex items-baseline gap-2">
                    <span className="text-2xl font-semibold">{percent(securitySpend, spend)}</span>
                    <span className="text-sm text-grey">
                      of spend, {formatUsd(securitySpend)} of {formatUsd(spend)}
                    </span>
                  </p>
                  <ShareBar
                    parts={stats.purposes.map((p) => ({
                      id: p.id,
                      value: p.cost,
                      color: purpose(p.id).color,
                      title: `${purpose(p.id).label}: ${formatUsd(p.cost)}`,
                    }))}
                  />
                  <table className="w-full border-separate border-spacing-0 text-sm tabular-nums [&_tbody_tr:last-child_td]:border-b-0">
                    <thead>
                      <tr>
                        <th className={`${TH} text-left`}>Model calls</th>
                        <th className={`${TH} text-right`}>Calls</th>
                        <th className={`${TH} text-right`}>Tokens</th>
                        <th className={`${TH} text-right`}>Cost</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.purposes.map((p) => (
                        <tr key={p.id}>
                          <td className={TD}>
                            <span className="flex items-center gap-1.5">
                              <span className={`size-2 rounded-full ${purpose(p.id).color}`} />
                              {purpose(p.id).label}
                            </span>
                          </td>
                          <td className={`${NUM}`}>{formatNumber(p.calls)}</td>
                          <td className={`${NUM}`}>{formatNumber(p.tokens)}</td>
                          <td className={`${NUM}`}>{formatUsd(p.cost)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              ) : (
                <Empty>No model calls yet</Empty>
              )}
            </Panel>

            <Panel title="Security layer time" wide>
              {allTime > 0 ? (
                <div className="grid grid-cols-2 grid-rows-[auto_auto_1fr] gap-x-8">
                  <p className="col-start-1 row-start-1 flex items-baseline gap-2 self-baseline">
                    <span className="text-2xl font-semibold">{percent(securityTime, allTime)}</span>
                    <span className="text-sm text-grey">
                      of turn time, {formatNumber(securityTime / events.length)} ms of a{' '}
                      {formatNumber(allTime / events.length)} ms turn on average
                    </span>
                  </p>
                  <div className="col-start-1 row-start-2">
                    <ShareBar
                      parts={stats.time.map((t) => ({
                        id: t.id,
                        value: t.total,
                        color: group(t.id).color,
                        title: `${group(t.id).label}: ${formatNumber(t.total / events.length)} ms per turn`,
                      }))}
                    />
                  </div>
                  <table className="col-start-1 row-start-3 w-full border-separate border-spacing-0 text-sm tabular-nums [&_tbody_tr:last-child_td]:border-b-0">
                    <thead>
                      <tr>
                        <th className={`${TH} text-left`}>Spent on</th>
                        <th className={`${TH} text-right`} title="Median, over the turns it ran in">
                          p50
                        </th>
                        <th className={`${TH} text-right`} title="95th percentile, over the turns it ran in">
                          p95
                        </th>
                        <th className={`${TH} text-right`}>Slowest</th>
                        <th className={`${TH} text-right`}>Share</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.time.map((t) => (
                        <tr key={t.id}>
                          <td className={TD} title={group(t.id).hint}>
                            <span className="flex items-center gap-1.5">
                              <span className={`size-2 rounded-full ${group(t.id).color}`} />
                              {group(t.id).label}
                            </span>
                          </td>
                          <td className={`${NUM}`}>{formatNumber(t.p50)} ms</td>
                          <td className={`${NUM}`}>{formatNumber(t.p95)} ms</td>
                          <td className={`${NUM}`}>{formatNumber(t.slowest)} ms</td>
                          <td className={`${NUM}`}>{percent(t.total, allTime)}</td>
                        </tr>
                      ))}
                    </tbody>
                    <tfoot className="font-medium">
                      <tr>
                        <td className={`${TD} border-t border-b-0`}>Whole turn</td>
                        <td className={`${NUM} border-t border-b-0`}>{formatNumber(stats.turnTime.p50)} ms</td>
                        <td className={`${NUM} border-t border-b-0`}>{formatNumber(stats.turnTime.p95)} ms</td>
                        <td className={`${NUM} border-t border-b-0`}>{formatNumber(stats.turnTime.slowest)} ms</td>
                        <td className={`${TD} border-t border-b-0`} />
                      </tr>
                    </tfoot>
                  </table>
                  {/* The turns take the breakdown's height without adding to it: from the headline's top
                      to the last table row, whose text the last turn's text shares a baseline with (the
                      table's 20px lines sit 2px lower than these 16px ones). Each turn sits at the foot
                      of an equal slot, so a short log still fills from the top at the same pitch. */}
                  <div className="relative col-start-2 row-span-3 row-start-1">
                    <div className="absolute inset-x-0 top-0 bottom-[calc(var(--cell)+2px)] flex flex-col">
                      <h3 className="px-1.5 text-[13px] text-grey">Last {RECENT_TURNS} turns</h3>
                      <div
                        className="grid flex-1"
                        style={{ gridTemplateRows: `repeat(${RECENT_TURNS}, minmax(0, 1fr))` }}
                      >
                        {stats.turns.map((t) => {
                          const timed = t.parts.reduce((sum, p) => sum + p.ms, 0)
                          return (
                            <button
                              key={t.id}
                              onClick={() => onOpenLogs({ query: `id:${t.id}` })}
                              title={`Open the log: id:${t.id}`}
                              className="grid w-full grid-cols-[4.5rem_1fr_5rem] items-center gap-3 self-end rounded-sm px-1.5 text-left text-sm/4 tabular-nums hover:bg-blue-light/30"
                            >
                              <span className="text-grey">{timeOf(t.time)}</span>
                              <span className="flex h-2.5" style={{ width: `${(t.latencyMs / slowestTurn) * 100}%` }}>
                                {/* The white right border is the 2px gap, so segments keep their true widths. */}
                                {t.parts.map((p, i) => (
                                  <span
                                    key={i}
                                    title={`${group(p.group).label}: ${formatNumber(p.ms)} ms`}
                                    className={`h-full border-r-2 border-white last:rounded-r-sm last:border-r-0 ${group(p.group).color}`}
                                    style={{ width: `${(p.ms / timed) * 100}%` }}
                                  />
                                ))}
                              </span>
                              <span className="text-right">{formatNumber(t.latencyMs)} ms</span>
                            </button>
                          )
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <Empty>No timed turns yet</Empty>
              )}
            </Panel>

            <Panel wide>
              <table className="w-full border-separate border-spacing-0 text-sm tabular-nums [&_tbody_tr:last-child_td]:border-b-0">
                <thead>
                  <tr>
                    <th className={`${TH} text-left`}>User</th>
                    <th className={`${TH} text-right`}>Turns</th>
                    <th className={`${TH} text-right`}>Blocked</th>
                    <th className={`${TH} text-right`}>Hidden</th>
                    <th className={`${TH} text-right`}>Refused</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.users.slice(0, 8).map((u) => (
                    <tr
                      key={u.user}
                      onClick={() => onOpenLogs({ query: `user:"${u.user}"` })}
                      className="cursor-pointer hover:bg-blue-light/30"
                    >
                      <td className={`${TD} w-full max-w-0`}>
                        <button
                          className="flex w-full items-baseline gap-2 text-left"
                          title={`Open the log: user:"${u.user}"`}
                        >
                          <span className="truncate">{u.user}</span>
                          <span className="shrink-0 text-[13px] text-grey">{u.role}</span>
                        </button>
                      </td>
                      <td className={`${NUM}`}>{formatNumber(u.turns)}</td>
                      <td className={`${NUM}`}>
                        <Count n={u.blocked} />
                      </td>
                      <td className={`${NUM}`}>
                        <Count n={u.hidden} />
                      </td>
                      <td className={`${NUM}`}>
                        <Count n={u.refused} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        )}
      </div>
    </div>
  )
}
