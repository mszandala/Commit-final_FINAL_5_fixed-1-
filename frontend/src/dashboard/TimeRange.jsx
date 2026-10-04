import { useEffect, useMemo, useState } from 'react'
import { DayPicker } from 'react-day-picker'
import { enGB } from 'react-day-picker/locale'
import { CalendarDays, ChevronLeft, ChevronRight } from 'lucide-react'
import Dropdown from '../ui/Dropdown'

// The log's time window: a preset counted back from now, or a fixed range picked on the calendar.
// A range is `{ preset }` or `{ from, to }`, where `to` is the last minute included.
const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
export const PRESETS = [
  { id: '1h', label: 'Last hour', ms: HOUR },
  { id: '24h', label: 'Last 24 hours', ms: DAY },
  { id: '7d', label: 'Last 7 days', ms: 7 * DAY },
  { id: '30d', label: 'Last 30 days', ms: 30 * DAY },
  { id: 'all', label: 'All time' },
]
const PRESET_BY_ID = Object.fromEntries(PRESETS.map((p) => [p.id, p]))

// [start, end) in ms for a range at `now`; null bounds are open.
export function bounds(range, now) {
  if (range.preset) {
    const { ms } = PRESET_BY_ID[range.preset]
    return ms ? [now - ms, null] : [null, null]
  }
  return [range.from.getTime(), range.to.getTime() + MINUTE]
}

// Rerenders every half minute while a preset counts back from now, so old rows leave the window.
export function useNow(range) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!range.preset || range.preset === 'all') return
    setNow(Date.now())
    const timer = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(timer)
  }, [range])
  return now
}

const dayOf = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
const fullDayOf = (d) => d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
const hhmm = (d) => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
const sameDay = (a, b) => a.toDateString() === b.toDateString()
const dayStart = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
// Two days in calendar order.
const ordered = (a, b) => (dayStart(a) <= dayStart(b) ? [a, b] : [b, a])
const within = (d, [a, b]) => dayStart(a) <= dayStart(d) && dayStart(d) <= dayStart(b)

export function rangeLabel(range) {
  if (range.preset) return PRESET_BY_ID[range.preset].label
  const { from, to } = range
  return sameDay(from, to)
    ? `${dayOf(from)}, ${hhmm(from)}–${hhmm(to)}`
    : `${dayOf(from)} ${hhmm(from)} – ${dayOf(to)} ${hhmm(to)}`
}

// "14:05" on `day` -> a Date, or null for an empty or half-typed time.
function at(day, time) {
  const m = /^(\d{2}):(\d{2})$/.exec(time)
  if (!day || !m) return null
  const d = new Date(day)
  d.setHours(Number(m[1]), Number(m[2]), 0, 0)
  return d
}

const Chevron = ({ orientation }) =>
  orientation === 'left' ? <ChevronLeft size={16} /> : <ChevronRight size={16} />

// Only our classes: the library's stylesheet is not loaded. A range's days share a light band;
// its ends are navy (hovering keeps them navy). Days with log rows carry a dot.
const CALENDAR = {
  root: 'relative w-fit text-sm',
  months: 'relative',
  month_caption: 'flex h-8 items-center justify-center px-9 font-semibold text-navy',
  nav: 'pointer-events-none absolute inset-x-0 top-0 z-10 flex h-8 items-center justify-between',
  button_previous:
    'pointer-events-auto grid size-8 place-items-center rounded-md text-grey hover:bg-page hover:text-ink disabled:pointer-events-none disabled:opacity-30',
  button_next:
    'pointer-events-auto grid size-8 place-items-center rounded-md text-grey hover:bg-page hover:text-ink disabled:pointer-events-none disabled:opacity-30',
  month_grid: 'mt-2 border-collapse',
  weekday: 'h-7 w-9 text-center text-[12px] font-normal text-grey',
  day: 'relative size-9 p-0 text-center',
  day_button:
    'size-9 rounded-md tabular-nums outline-none hover:bg-blue-light focus-visible:ring-2 focus-visible:ring-blue disabled:hover:bg-transparent',
}
const DAY_STATES = {
  today: 'font-semibold text-navy',
  outside: 'text-grey/40',
  disabled: 'text-grey/30 [&>button]:cursor-default',
  band: 'bg-blue-light/40',
  band_start: 'rounded-l-md',
  band_end: 'rounded-r-md',
  edge: '[&>button]:bg-navy [&>button]:text-white [&>button]:hover:bg-navy',
  logged:
    "after:pointer-events-none after:absolute after:bottom-1 after:left-1/2 after:size-1 after:-translate-x-1/2 after:rounded-full after:bg-blue after:content-['']",
}

function TimeField({ label, day, time, onChange, invalid }) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="w-9 text-grey">{label}</span>
      <span className="w-24 tabular-nums">{day ? fullDayOf(day) : <span className="text-grey/60">Pick a day</span>}</span>
      <input
        type="time"
        required
        value={time}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid}
        className="rounded-md border border-line bg-white px-2 py-1 tabular-nums outline-none focus:border-blue aria-invalid:border-red [&::-webkit-calendar-picker-indicator]:hidden"
      />
    </label>
  )
}

// The panel's own copy of the range, applied only on Apply; presets apply at once.
// Days: the first click starts a range and the second ends it, in either order; the next click
// starts a new one. Between the two clicks the band follows the pointer. Until the second click
// the range is the one day.
function Picker({ range, now, loggedDays, firstDay, onChange, close }) {
  const [start, end] = bounds(range, now)
  const initialFrom = new Date(start ?? firstDay?.getTime() ?? now - DAY)
  const initialTo = new Date(end ? end - MINUTE : now)
  const [days, setDays] = useState({ from: initialFrom, to: initialTo })
  const [hovered, setHovered] = useState(null)
  const [times, setTimes] = useState({ from: hhmm(initialFrom), to: hhmm(initialTo) })
  // Picking days resets the times to whole days until someone edits a time by hand.
  const [timesEdited, setTimesEdited] = useState(false)

  const picking = !days.to
  const toDay = days.to ?? days.from
  const from = at(days.from, times.from)
  const to = at(toDay, times.to)
  const band = picking && hovered ? ordered(days.from, hovered) : [days.from, toDay]

  const pick = (day) => {
    if (picking) {
      const [a, b] = ordered(days.from, day)
      setDays({ from: a, to: b })
    } else {
      setDays({ from: day, to: null })
    }
    if (!timesEdited) setTimes({ from: '00:00', to: '23:59' })
  }
  const backwards = from && to && to < from
  const ready = from && to && !backwards

  const apply = (e) => {
    e.preventDefault()
    if (!ready) return
    onChange({ from, to })
    close()
  }

  return (
    <div className="flex">
      <div className="flex w-40 flex-col gap-0.5 border-r border-line p-2">
        {PRESETS.map((p) => (
          <button
            key={p.id}
            onClick={() => {
              onChange({ preset: p.id })
              close()
            }}
            className={`rounded-md px-2.5 py-1.5 text-left text-sm ${
              range.preset === p.id ? 'bg-blue-light text-ink' : 'text-grey hover:bg-page hover:text-ink'
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>
      <form onSubmit={apply} className="flex flex-col gap-3 p-3">
        <DayPicker
          onDayClick={(day, modifiers) => !modifiers.disabled && pick(day)}
          onDayMouseEnter={(day, modifiers) => setHovered(modifiers.disabled ? null : day)}
          onDayMouseLeave={() => setHovered(null)}
          defaultMonth={toDay}
          locale={enGB}
          weekStartsOn={1}
          showOutsideDays
          disabled={{ after: new Date(now) }}
          endMonth={new Date(now)}
          modifiers={{
            selected: (d) => within(d, [days.from, toDay]),
            edge: (d) => sameDay(d, days.from) || sameDay(d, toDay),
            band: (d) => !sameDay(band[0], band[1]) && within(d, band),
            band_start: (d) => sameDay(d, band[0]),
            band_end: (d) => sameDay(d, band[1]),
            logged: (d) => loggedDays.has(d.toDateString()),
          }}
          classNames={CALENDAR}
          modifiersClassNames={DAY_STATES}
          components={{ Chevron }}
        />
        <div className="flex flex-col gap-1.5 border-t border-line pt-3">
          <TimeField
            label="From"
            day={days.from}
            time={times.from}
            onChange={(t) => {
              setTimes({ ...times, from: t })
              setTimesEdited(true)
            }}
          />
          <TimeField
            label="To"
            day={toDay}
            time={times.to}
            invalid={backwards}
            onChange={(t) => {
              setTimes({ ...times, to: t })
              setTimesEdited(true)
            }}
          />
        </div>
        <div className="flex items-center justify-end gap-2">
          {backwards && <span className="mr-auto text-[13px] text-red-text">Ends before it starts</span>}
          <button type="button" onClick={close} className="rounded-md px-2.5 py-1 text-sm text-grey hover:bg-page hover:text-ink">
            Cancel
          </button>
          <button
            type="submit"
            disabled={!ready}
            className="rounded-md bg-navy px-3 py-1 text-sm text-white disabled:opacity-40"
          >
            Apply
          </button>
        </div>
      </form>
    </div>
  )
}

export default function TimeRange({ range, onChange, now, events }) {
  // Days with rows get a dot; the calendar opens no earlier than the first of them.
  const loggedDays = useMemo(() => new Set(events.map((e) => e.time.toDateString())), [events])
  const firstDay = events[0]?.time

  return (
    <Dropdown
      variant="filter"
      label="Time range"
      trigger={
        <>
          <CalendarDays size={14} className="text-grey" />
          <span className="whitespace-nowrap tabular-nums">{rangeLabel(range)}</span>
        </>
      }
    >
      {(close) => (
        <Picker
          range={range}
          now={now}
          loggedDays={loggedDays}
          firstDay={firstDay}
          onChange={onChange}
          close={close}
        />
      )}
    </Dropdown>
  )
}
