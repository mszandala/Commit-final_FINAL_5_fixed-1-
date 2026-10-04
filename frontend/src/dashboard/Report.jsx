import { useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import { createPortal } from 'react-dom'
import { Download, Printer } from 'lucide-react'
import { getRoles } from '../api'
import { getEvents, subscribeEvents } from '../events'
import { formatNumber, formatUsd } from '../format'
import { useMeta } from '../meta'
import Button from '../ui/Button'
import { tightestLimit } from '../ui/BudgetBar'
import PeoplePicker from './PeoplePicker'
import TimeRange, { bounds, useNow } from './TimeRange'
import { fold } from './search'
import { controlCounts, isBlocked, isHidden, isRefused, percentile, turnCost } from './turns'

// A report on one period, for everyone or chosen people, built in the browser from the log. It prints
// to PDF (only the report goes on paper) and downloads its turns as CSV for a spreadsheet.

const GUARD_MODES = { warn: 'Warn only', block: 'Block' }

const stamp = (d) =>
  d.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
const pad = (n) => String(n).padStart(2, '0')
const isoDay = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
const slug = (s) =>
  fold(s)
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
const percent = (part, whole) => (whole ? `${Math.round((part / whole) * 100)}%` : '0%')

// `picked` people are listed even without turns in the period.
function summarize(turns, picked) {
  const blank = (p) => ({ ...p, turns: 0, blocked: 0, hidden: 0, refused: 0, cost: 0 })
  const people = Object.fromEntries(picked.map((p) => [p.user, blank(p)]))
  let chat = 0
  let security = 0
  for (const e of turns) {
    const cost = turnCost(e)
    chat += cost.chat
    security += cost.security
    const p = (people[e.user] ??= blank({ user: e.user, role: e.role, roleId: e.roleId }))
    // Live test turns share one user across roles.
    if (p.role !== e.role) p.role = ''
    p.turns++
    p.blocked += isBlocked(e)
    p.hidden += isHidden(e)
    p.refused += isRefused(e)
    p.cost += cost.chat
  }
  return {
    turns: turns.length,
    blocked: turns.filter(isBlocked).length,
    hidden: turns.filter(isHidden).length,
    refused: turns.filter(isRefused).length,
    chat,
    security,
    medianMs: percentile(
      turns.map((e) => e.latencyMs),
      50,
    ),
    controls: controlCounts(turns),
    people: Object.values(people).sort(
      (a, b) => b.blocked + b.refused - (a.blocked + a.refused) || b.hidden - a.hidden || b.turns - a.turns,
    ),
    incidents: turns.filter((e) => isBlocked(e) || isRefused(e)),
  }
}

// One row per turn, oldest first. Text that starts like a formula gets a leading quote, so a
// prompt such as "=HYPERLINK(...)" stays text when the file is opened in a spreadsheet.
const CSV_COLUMNS = [
  ['id', (e) => e.id],
  ['time', (e) => e.time.toISOString()],
  ['user', (e) => e.user],
  ['role', (e) => e.role],
  ['decision', (e) => e.decision],
  ['level', (e) => e.level],
  ['control', (e) => e.control],
  ['reason', (e) => e.reason],
  [
    'flagged_steps',
    (e) =>
      e.steps
        .filter((s) => s.level !== 'info')
        .map((s) => `${s.label}: ${s.summary}`)
        .join(' | '),
  ],
  ['hidden_data', (e) => e.hidden.join(' ')],
  ['model', (e) => e.model],
  ['tokens', (e) => e.tokens],
  ['chatbot_cost_usd', (e) => turnCost(e).chat.toFixed(6)],
  ['security_cost_usd', (e) => turnCost(e).security.toFixed(6)],
  ['latency_ms', (e) => e.latencyMs],
  ['conversation', (e) => e.conversationId],
  ['prompt_sent_to_model', (e) => e.maskedPrompt ?? ''],
]

function csvCell(value) {
  let s = String(value ?? '')
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function downloadCsv(turns, name) {
  const lines = [CSV_COLUMNS.map(([h]) => h), ...turns.map((e) => CSV_COLUMNS.map(([, get]) => get(e)))]
  // The byte order mark makes Excel read the file as UTF-8, so Polish letters survive.
  const text = '\ufeff' + lines.map((row) => row.map(csvCell).join(',')).join('\r\n')
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${name}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// The browser names the PDF after the page title.
function printAs(name) {
  const title = document.title
  document.title = name
  window.addEventListener('afterprint', () => (document.title = title), { once: true })
  window.print()
}

const TH = 'whitespace-nowrap border-b border-line px-1.5 py-1.5 text-[13px] font-normal text-grey'
// Long names and unbroken strings (a pasted URL in a reason) break wherever they must, so a table
// never grows past the page.
const TD = 'border-b border-line px-1.5 py-1.5 align-top [overflow-wrap:anywhere]'
const NUM = `${TD} whitespace-nowrap text-right`
const TABLE =
  'w-full border-separate border-spacing-0 tabular-nums [&_tbody_tr:last-child_td]:border-b-0 [&_tr]:break-inside-avoid'

const Count = ({ n }) => (n ? formatNumber(n) : <span className="text-grey">&ndash;</span>)

function Section({ title, children }) {
  return (
    <section className="mt-7">
      <h2 className="mb-1.5 break-after-avoid font-semibold text-navy">{title}</h2>
      {children}
    </section>
  )
}

const None = ({ children }) => <p className="py-1.5 text-grey">{children}</p>

function ReportDoc({ people, from, to, generated, report, budgets, config }) {
  const person = people.length === 1 ? people[0] : null
  const meta = useMeta()
  const model = meta.models.find((m) => m.id === config.model)?.label ?? config.model
  const sensitivity =
    meta.sensitivityLevels.find((l) => l.id === config.sensitivity)?.label ?? `Custom (${config.piiThreshold})`
  const budget = person && budgets[person.user]
  // Guards switched off in the config; a report saying "Prompt guard: Block" must not hide that it is off.
  const off = (meta.filters ?? []).filter((f) => config.filters?.[f.id] === false).map((f) => f.label)

  const figures = [
    { label: 'Turns', value: formatNumber(report.turns) },
    {
      label: 'Blocked',
      value: formatNumber(report.blocked),
      note: `${percent(report.blocked, report.turns)} of turns`,
    },
    {
      label: 'Data hidden',
      value: formatNumber(report.hidden),
      note: `${percent(report.hidden, report.turns)} of turns`,
    },
    { label: 'Refused', value: formatNumber(report.refused) },
    {
      label: 'Spend',
      value: formatUsd(report.chat + report.security),
      note: `${formatUsd(report.security)} on checks`,
    },
    { label: 'Median turn', value: `${formatNumber(report.medianMs)} ms` },
  ]

  return (
    <article className="text-sm">
      <header className="flex items-start justify-between gap-6 border-b border-line pb-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-navy">Security report</h1>
          <p className="mt-1 text-[15px] [overflow-wrap:anywhere]">
            {person
              ? [person.user, person.role].filter(Boolean).join(', ')
              : people.length
                ? people.map((p) => p.user).join(', ')
                : 'All users'}
          </p>
          <p className="text-grey tabular-nums">
            {stamp(from)} – {stamp(to)}
          </p>
        </div>
        <p className="shrink-0 pt-1 text-[13px] text-grey tabular-nums">Generated {stamp(generated)}</p>
      </header>

      {report.turns === 0 ? (
        <None>No turns in this period</None>
      ) : (
        <>
          <dl className="grid grid-cols-[repeat(auto-fit,minmax(5.5rem,1fr))] gap-x-4 gap-y-4 border-b border-line py-5">
            {figures.map((f) => (
              <div key={f.label} className="flex flex-col">
                <dt className="text-[13px] text-grey">{f.label}</dt>
                <dd className="mt-1 whitespace-nowrap text-xl font-semibold tabular-nums">{f.value}</dd>
                {f.note && <dd className="text-[13px] text-grey">{f.note}</dd>}
              </div>
            ))}
          </dl>

          <Section title="Controls that fired">
            {report.controls.length ? (
              <table className={TABLE}>
                <thead>
                  <tr>
                    <th className={`${TH} text-left`}>Control</th>
                    <th className={`${TH} text-right`}>Blocked</th>
                    <th className={`${TH} text-right`}>Warnings</th>
                    <th className={`${TH} text-right`}>Share of turns</th>
                  </tr>
                </thead>
                <tbody>
                  {report.controls.map((c) => (
                    <tr key={c.kind}>
                      <td className={`${TD} w-full`}>{meta.stepKinds[c.kind] ?? c.kind}</td>
                      <td className={NUM}>
                        <Count n={c.block} />
                      </td>
                      <td className={NUM}>
                        <Count n={c.warn} />
                      </td>
                      <td className={NUM}>{percent(c.block + c.warn, report.turns)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <None>No control fired in this period</None>
            )}
          </Section>

          {!person && (
            <Section title="By user">
              <table className={TABLE}>
                <thead>
                  <tr>
                    <th className={`${TH} text-left`}>User</th>
                    <th className={`${TH} text-right`}>Turns</th>
                    <th className={`${TH} text-right`}>Blocked</th>
                    <th className={`${TH} text-right`}>Hidden</th>
                    <th className={`${TH} text-right`}>Refused</th>
                    <th className={`${TH} text-right`}>Spend</th>
                    <th
                      className={`${TH} text-right`}
                      title="Today's tokens or the spending limit, whichever is closer"
                    >
                      Budget now
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {report.people.map((p) => {
                    const b = budgets[p.user]
                    return (
                      <tr key={p.user}>
                        <td className={`${TD} w-full`}>
                          {p.user}
                          <span className="ml-2 text-[13px] text-grey">{p.role}</span>
                        </td>
                        <td className={NUM}>{formatNumber(p.turns)}</td>
                        <td className={NUM}>
                          <Count n={p.blocked} />
                        </td>
                        <td className={NUM}>
                          <Count n={p.hidden} />
                        </td>
                        <td className={NUM}>
                          <Count n={p.refused} />
                        </td>
                        <td className={NUM}>{formatUsd(p.cost)}</td>
                        <td
                          className={NUM}
                          title={
                            b &&
                            `${formatNumber(b.used)} of ${formatNumber(b.limit)} tokens today, ${formatUsd(b.spent)} of ${formatUsd(b.spendingLimit)} spent`
                          }
                        >
                          {b ? (
                            `${Math.round(tightestLimit(b).share * 100)}%`
                          ) : (
                            <span className="text-grey">&ndash;</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </Section>
          )}

          <Section title="Blocked and refused turns">
            {report.incidents.length ? (
              <table className={TABLE}>
                <thead>
                  <tr>
                    <th className={`${TH} text-left`}>Time</th>
                    {!person && <th className={`${TH} w-32 text-left`}>User</th>}
                    <th className={`${TH} text-left`}>Outcome</th>
                    <th className={`${TH} w-28 text-left`}>Control</th>
                    <th className={`${TH} text-left`}>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {report.incidents.map((e) => {
                    // A refused turn's own verdict can be another control's (data hidden in the
                    // reply), so it is described by its refusal step.
                    const refusal = !isBlocked(e) && e.steps.find((s) => s.kind === 'refusal')
                    const control = refusal ? meta.stepKinds.refusal : e.control
                    const reason = refusal ? refusal.summary : e.reason
                    return (
                      <tr key={e.id}>
                        <td className={`${TD} whitespace-nowrap`}>{stamp(e.time)}</td>
                        {!person && <td className={TD}>{e.user}</td>}
                        <td className={`${TD} whitespace-nowrap`}>
                          <span className="flex items-center gap-1.5">
                            <span className={`size-1.5 rounded-full ${isBlocked(e) ? 'bg-red' : 'bg-amber'}`} />
                            {isBlocked(e) ? 'Blocked' : 'Refused'}
                          </span>
                        </td>
                        <td className={TD}>{control || <span className="text-grey">&ndash;</span>}</td>
                        <td className={`${TD} text-grey`}>{reason}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            ) : (
              <None>None in this period</None>
            )}
          </Section>
        </>
      )}

      <Section title="When generated">
        <dl className="grid grid-cols-[10rem_minmax(0,1fr)] gap-y-1 [overflow-wrap:anywhere]">
          {budget && (
            <>
              <dt className="text-grey">Budget</dt>
              <dd className="tabular-nums">
                {formatNumber(budget.used)} of {formatNumber(budget.limit)} tokens today, {formatUsd(budget.spent)} of{' '}
                {formatUsd(budget.spendingLimit)} spent
              </dd>
            </>
          )}
          <dt className="text-grey">Model</dt>
          <dd>{model}</dd>
          <dt className="text-grey">Prompt guard</dt>
          <dd>{GUARD_MODES[config.guardMode] ?? config.guardMode}</dd>
          <dt className="text-grey">PII sensitivity</dt>
          <dd>{sensitivity}</dd>
          <dt className="text-grey">Mask PII in chat</dt>
          <dd>{config.maskPii ? 'On' : 'Off'}</dd>
          <dt className="text-grey">Switched off</dt>
          <dd className={off.length ? 'text-amber-text' : ''}>{off.length ? off.join(', ') : 'None'}</dd>
        </dl>
      </Section>
    </article>
  )
}

export default function Report({ config }) {
  const all = useSyncExternalStore(subscribeEvents, getEvents)
  const [range, setRange] = useState({ preset: '7d' })
  const now = useNow(range)
  // Names in the order they were added; none means everyone.
  const [selected, setSelected] = useState([])
  // Budgets are the state right now, not over the period; reloaded with the log.
  const [roles, setRoles] = useState([])
  useEffect(() => {
    getRoles().then(setRoles, () => {})
  }, [all])

  const [start, end] = bounds(range, now)
  const from = range.preset ? new Date(start ?? all[0]?.time ?? now) : range.from
  const to = range.preset ? new Date(now) : range.to

  // Each role's example user first, then anyone else the log has seen.
  const people = useMemo(() => {
    const list = roles.map((r) => ({ user: r.user, role: r.label, roleId: r.id }))
    for (const e of all)
      if (!list.some((p) => p.user === e.user)) list.push({ user: e.user, role: e.role, roleId: e.roleId })
    return list
  }, [roles, all])
  // A name the people list no longer has (after a role change) drops out of the report and its chip.
  const picked = selected.map((user) => people.find((p) => p.user === user)).filter(Boolean)
  const names = picked.map((p) => p.user)

  const inPeriod = all.filter((e) => (start === null || e.time >= start) && (end === null || e.time < end))
  const counts = {}
  for (const e of inPeriod) counts[e.user] = (counts[e.user] ?? 0) + 1
  const turns = names.length ? inPeriod.filter((e) => names.includes(e.user)) : inPeriod
  const report = useMemo(() => summarize(turns, picked), [all, start, end, selected, people])
  // A budget belongs to a role's example user; live test turns use the roles without their budgets.
  const budgets = Object.fromEntries(roles.map((r) => [r.user, r.budget]))
  const who = !picked.length
    ? 'all-users'
    : picked.length <= 3
      ? picked.map((p) => slug(p.user)).join('_')
      : `${picked.length}-users`
  const name = `security-report_${who}_${isoDay(from)}_${isoDay(to)}`

  const doc = (
    <ReportDoc
      people={picked}
      from={from}
      to={to}
      generated={new Date(now)}
      report={report}
      budgets={budgets}
      config={config}
    />
  )

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-start gap-3 px-6 py-4">
        <TimeRange range={range} onChange={setRange} now={now} events={all} />
        <PeoplePicker people={people} selected={names} onChange={setSelected} counts={counts} />
        {/* Centred on the 34px fields of the first row. */}
        <div className="ml-auto mt-0.5 flex gap-2">
          <Button
            size="sm"
            icon={Download}
            disabled={!turns.length}
            onClick={() => downloadCsv(turns, name)}
            title="Every turn in the report, one row each"
          >
            CSV
          </Button>
          <Button size="sm" icon={Printer} onClick={() => printAs(name)} title="Print or save as PDF">
            PDF
          </Button>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-6 pb-5">
        <div className="mx-auto max-w-4xl rounded-md border border-line bg-white px-10 py-8">{doc}</div>
      </div>
      {/* Only this copy goes on paper; index.css hides everything else in the body when printing.
          The page margins live here rather than in @page, which the print dialog's Margins setting
          can override: side padding, and an empty header and footer row that the browser repeats at
          the top and bottom of every page. */}
      {createPortal(
        <table className="print-report hidden w-full print:table">
          <thead>
            <tr>
              <td className="h-[14mm] p-0" />
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="px-[16mm] py-0">{doc}</td>
            </tr>
          </tbody>
          <tfoot>
            <tr>
              <td className="h-[14mm] p-0" />
            </tr>
          </tfoot>
        </table>,
        document.body,
      )}
    </div>
  )
}
