import { Fragment, useEffect, useRef, useState } from 'react'
import { Check, ChevronRight, CircleAlert, ExternalLink, LoaderCircle, Minus, Play, RotateCw, X } from 'lucide-react'
import { getTestRun, getTests, startTestRun } from '../api'
import { refreshEvents } from '../events'
import { formatNumber, formatUsd } from '../format'
import { useMeta } from '../meta'
import Button from '../ui/Button'

// Live tests: each scenario is a real chat turn through the security layer and the configured model.
// The backend runs them one by one in the background; this tab polls the run while it lasts.

const POLL_MS = 1500

const OUTCOMES = {
  allowed: { label: 'Allowed', dot: 'bg-green' },
  redacted: { label: 'Redacted', dot: 'bg-amber' },
  denied: { label: 'Denied', dot: 'bg-red' },
  blocked: { label: 'Blocked', dot: 'bg-red' },
  error: { label: 'Error', dot: 'bg-grey' },
}

const STATUS = {
  passed: { icon: Check, className: 'text-green-text', label: 'Passed' },
  failed: { icon: X, className: 'text-red-text', label: 'Failed' },
  error: { icon: CircleAlert, className: 'text-amber-text', label: 'Error' },
  running: { icon: LoaderCircle, className: 'animate-spin text-blue', label: 'Running' },
  queued: { icon: Minus, className: 'text-blue', label: 'Queued' },
  idle: { icon: Minus, className: 'text-line', label: 'Not run' },
}

const LIMIT_LABELS = {
  maxPromptChars: (v) => `Prompt limit: ${formatNumber(v)} chars`,
  maxTurnTokens: (v) => `Turn limit: ${formatNumber(v)} tokens`,
  maxTurnCost: (v) => `Turn limit: ${formatUsd(v)}`,
}

const asList = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v])

// The settings a scenario changes for its own turn, as short labels.
function configLabels(config = {}, meta) {
  const filterLabel = (id) => meta.filters.find((f) => f.id === id)?.label ?? id
  const areaLabel = (id) => meta.dataAccess.find((a) => a.id === id)?.label ?? id
  return [
    config.guardMode && `Guard mode: ${config.guardMode}`,
    config.maskPii !== undefined && `Masking: ${config.maskPii ? 'on' : 'off'}`,
    ...Object.entries(config.filters ?? {}).map(([id, on]) => `${filterLabel(id)}: ${on ? 'on' : 'off'}`),
    ...Object.entries(config.roles ?? {}).map(([role, areas]) => `${role} access: ${areas.map(areaLabel).join(', ')}`),
    ...Object.entries(config.limits ?? {}).map(([key, v]) => LIMIT_LABELS[key]?.(v) ?? `${key}: ${v}`),
  ].filter(Boolean)
}

function Outcome({ outcome, stage }) {
  const meta = useMeta()
  const o = OUTCOMES[outcome]
  if (!o) return <span className="text-grey">&ndash;</span>
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`size-1.5 shrink-0 rounded-full ${o.dot}`} />
      {o.label}
      {stage && <span className="truncate text-grey">· {meta.controls[stage] ?? stage}</span>}
    </span>
  )
}

function Expected({ expect }) {
  const meta = useMeta()
  const outcomes = asList(expect.outcome).map((o) => OUTCOMES[o]?.label ?? o)
  const stages = asList(expect.stage).map((s) => meta.controls[s] ?? s)
  const parts = [outcomes.join(' or '), stages.length && `by ${stages.join(' or ')}`].filter(Boolean)
  return <span>{parts.join(' ') || 'Checks only'}</span>
}

function Field({ label, children }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-3 py-1">
      <span className="text-[13px] text-grey">{label}</span>
      <div className="min-w-0 text-sm">{children}</div>
    </div>
  )
}

function Details({ scenario, result, onOpenLogs }) {
  const meta = useMeta()
  const labels = configLabels(scenario.config, meta)
  return (
    <div className="space-y-1 bg-page/60 px-10 py-3">
      <Field label="Prompt">
        <span className="whitespace-pre-wrap">{scenario.prompt}</span>
      </Field>
      {labels.length > 0 && (
        <Field label="Settings">
          <span className="flex flex-wrap gap-1.5">
            {labels.map((l) => (
              <span key={l} className="rounded-sm bg-violet/15 px-1.5 py-px text-[13px]">
                {l}
              </span>
            ))}
          </span>
        </Field>
      )}
      {!result ? (
        <Field label="Result">
          <span className="text-grey">Not run yet</span>
        </Field>
      ) : (
        <>
          <Field label="Checks">
            {result.checks.length === 0 && <span className="text-red-text">{result.error}</span>}
            <ul className="space-y-0.5">
              {result.checks.map((c, i) => (
                <li key={i} className="flex items-baseline gap-2">
                  {c.ok ? (
                    <Check size={14} className="shrink-0 self-center text-green-text" />
                  ) : (
                    <X size={14} className="shrink-0 self-center text-red-text" />
                  )}
                  <span className="w-32 shrink-0">{c.name}</span>
                  <span className={c.ok ? 'text-grey' : 'text-red-text'}>{c.detail}</span>
                </li>
              ))}
            </ul>
          </Field>
          {result.reason && <Field label="Reason">{result.reason}</Field>}
          {result.maskedPrompt && result.maskedPrompt !== scenario.prompt && (
            <Field label="Model got">
              <span className="font-mono text-[12.5px]">{result.maskedPrompt}</span>
            </Field>
          )}
          {result.tools?.length > 0 && (
            <Field label="Tool calls">
              {result.tools.map((t, i) => (
                <span key={i} className="mr-3 inline-flex items-center gap-1.5 font-mono text-[12.5px]">
                  <span className={`size-1.5 rounded-full ${t.allowed ? 'bg-green' : 'bg-red'}`} />
                  {t.tool}
                  {!t.allowed && <span className="font-sans text-grey">({meta.controls[t.stage] ?? t.stage})</span>}
                </span>
              ))}
            </Field>
          )}
          <Field label="Reply">
            <pre className="whitespace-pre-wrap break-words rounded-md bg-white px-3 py-2 font-sans text-sm">
              {result.reply || <span className="text-grey">(no reply shown to the user)</span>}
            </pre>
          </Field>
          <Field label="Usage">
            <span className="text-grey">
              {result.modelCalls} model calls · {formatNumber(result.tokens)} tokens · {formatUsd(result.cost)} ·{' '}
              {formatNumber(result.latencyMs)} ms
            </span>
          </Field>
          {result.eventId && (
            <div className="pt-1">
              <Button size="sm" icon={ExternalLink} onClick={() => onOpenLogs({ query: `id:${result.eventId}` })}>
                Open in log
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

const TH = 'border-b border-line px-2 py-2 text-left text-[13px] font-normal text-grey'
const TD = 'border-b border-line px-2 py-2 align-middle'

export default function Tests({ onOpenLogs }) {
  const [catalog, setCatalog] = useState(null)
  const [run, setRun] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState({})
  const running = run?.status === 'running'
  const wasRunning = useRef(false)

  async function load() {
    setError(null)
    try {
      const [tests, current] = await Promise.all([getTests(), getTestRun()])
      setCatalog(tests)
      setRun(current)
    } catch (e) {
      setError(e.message)
    }
  }

  useEffect(() => {
    load()
  }, [])

  // Poll while a run lasts; when it ends, the log picks up the test turns.
  useEffect(() => {
    if (running) {
      wasRunning.current = true
      const timer = setInterval(async () => {
        try {
          setRun(await getTestRun())
        } catch (e) {
          setError(e.message)
        }
      }, POLL_MS)
      return () => clearInterval(timer)
    }
    if (wasRunning.current) {
      wasRunning.current = false
      refreshEvents()
    }
  }, [running])

  async function start(ids) {
    setError(null)
    try {
      setRun(await startTestRun(ids))
    } catch (e) {
      setError(e.message)
    }
  }

  if (!catalog) {
    return <div className="px-6 py-10 text-center text-grey">{error ?? 'Loading tests…'}</div>
  }

  const results = run?.results ?? {}
  const statusOf = (id) =>
    results[id]?.status ?? (run?.current === id ? 'running' : running && run.ids.includes(id) ? 'queued' : 'idle')
  const done = Object.values(results)
  const passed = done.filter((r) => r.status === 'passed').length
  const failedIds = done.filter((r) => r.status !== 'passed').map((r) => r.id)
  const cost = done.reduce((sum, r) => sum + (r.cost ?? 0), 0)
  const tokens = done.reduce((sum, r) => sum + (r.tokens ?? 0), 0)

  return (
    <div className="h-full overflow-auto">
      <div className="space-y-5 px-6 pb-8 pt-5">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div className="min-w-0 flex-1">
            <h2 className="font-semibold text-navy">Live tests</h2>
            <p className="text-sm text-grey">
              Each test is a real chat turn through the security layer and the model ({catalog.model}). Settings a test
              changes apply to its own turn only and are restored after it. Test turns appear in the log.
            </p>
          </div>
          {run && (
            <div className="flex gap-5 text-sm tabular-nums">
              <span>
                <span className="font-semibold text-green-text">{passed}</span>
                <span className="text-grey"> / {run.ids.length} passed</span>
              </span>
              {failedIds.length > 0 && <span className="text-red-text">{failedIds.length} failed</span>}
              <span className="text-grey">{formatNumber(tokens)} tokens</span>
              <span className="text-grey">{formatUsd(cost)}</span>
            </div>
          )}
          <div className="flex gap-2">
            {!running && failedIds.length > 0 && (
              <Button icon={RotateCw} onClick={() => start(failedIds)}>
                Rerun failed
              </Button>
            )}
            <Button variant="primary" icon={running ? LoaderCircle : Play} disabled={running} onClick={() => start()}>
              {running ? `Running ${done.length + 1} of ${run.ids.length}` : 'Run all'}
            </Button>
          </div>
        </div>
        {error && <p className="text-sm text-red-text">{error}</p>}

        {catalog.groups.map((group) => {
          const scenarios = catalog.scenarios.filter((s) => s.group === group.id)
          return (
            <section key={group.id} className="rounded-md border border-line bg-white">
              <div className="flex items-baseline justify-between gap-4 px-4 pb-1 pt-3">
                <div>
                  <h3 className="font-semibold text-navy">{group.label}</h3>
                  <p className="text-[13px] text-grey">{group.description}</p>
                </div>
                <Button size="sm" icon={Play} disabled={running} onClick={() => start(scenarios.map((s) => s.id))}>
                  Run group
                </Button>
              </div>
              <table className="w-full table-fixed text-sm">
                <thead>
                  <tr>
                    <th className={`${TH} w-10`} />
                    <th className={TH}>Test</th>
                    <th className={`${TH} w-36`}>Role</th>
                    <th className={`${TH} w-56`}>Expected</th>
                    <th className={`${TH} w-56`}>Result</th>
                    <th className={`${TH} w-20 text-right`}>Latency</th>
                    <th className={`${TH} w-14`} />
                  </tr>
                </thead>
                <tbody>
                  {scenarios.map((s) => {
                    const result = results[s.id]
                    const status = STATUS[statusOf(s.id)]
                    const isOpen = open[s.id]
                    return (
                      <Fragment key={s.id}>
                        <tr
                          onClick={() => setOpen({ ...open, [s.id]: !isOpen })}
                          className="cursor-pointer hover:bg-blue-light/20"
                        >
                          <td className={`${TD} pl-4`} title={status.label}>
                            <status.icon size={16} className={status.className} />
                          </td>
                          <td className={TD}>
                            <span className="flex items-center gap-1.5">
                              <ChevronRight
                                size={14}
                                className={`shrink-0 text-grey transition-transform ${isOpen ? 'rotate-90' : ''}`}
                              />
                              <span className="truncate">{s.title}</span>
                              {s.config && <span className="shrink-0 rounded-sm bg-violet/15 px-1.5 text-xs">settings</span>}
                            </span>
                          </td>
                          <td className={`${TD} truncate`}>{s.roleLabel}</td>
                          <td className={`${TD} truncate text-grey`}>
                            <Expected expect={s.expect} />
                          </td>
                          <td className={`${TD} truncate`}>
                            {result ? <Outcome outcome={result.outcome ?? 'error'} stage={result.stage} /> : '–'}
                          </td>
                          <td className={`${TD} text-right tabular-nums text-grey`}>
                            {result ? `${(result.latencyMs / 1000).toFixed(1)} s` : ''}
                          </td>
                          <td className={`${TD} pr-4 text-right`}>
                            <button
                              aria-label={`Run ${s.title}`}
                              title="Run this test"
                              disabled={running}
                              onClick={(e) => {
                                e.stopPropagation()
                                start([s.id])
                              }}
                              className="rounded-md p-1 text-grey hover:bg-page hover:text-navy disabled:opacity-40"
                            >
                              <Play size={14} />
                            </button>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={7} className="border-b border-line p-0">
                              <Details scenario={s} result={result} onOpenLogs={onOpenLogs} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </section>
          )
        })}
      </div>
    </div>
  )
}
