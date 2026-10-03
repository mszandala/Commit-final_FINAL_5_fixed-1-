import { useState } from 'react'
import { Check, ChevronDown, Eye, EyeOff } from 'lucide-react'
import { useMeta } from '../meta'
import Button from '../ui/Button'
import Dropdown from '../ui/Dropdown'

const PROVIDERS = [
  { id: 'openrouter', label: 'OpenRouter' },
  { id: 'ollama', label: 'Ollama (local)' },
]

const GUARD_MODES = [
  { id: 'warn', label: 'Warn only', hint: 'Flags the request in the logs and lets it through' },
  { id: 'block', label: 'Block', hint: 'Stops the request before it reaches the model' },
]

// Hints for the levels in GET /meta -> sensitivityLevels.
const SENSITIVITY_HINTS = {
  low: 'Flags only clear-cut matches, fewer false alarms',
  balanced: 'Recommended for everyday use',
  high: 'Flags anything that looks like personal data',
}

// Rebuilt in a fixed order, so ticking something off and on again doesn't count as a change.
const toggle = (list, item, order) => order.filter((x) => (x === item) !== list.includes(x))

const field = 'rounded-md border border-line bg-white py-1.5 text-sm outline-none focus:border-blue'

function Section({ title, children }) {
  return (
    <section>
      <h2 className="mb-2.5 font-semibold text-navy">{title}</h2>
      <div className="rounded-md border border-line bg-white">{children}</div>
    </section>
  )
}

function Row({ label, children }) {
  return (
    <div className="grid grid-cols-[1fr_26rem_1fr] items-start gap-6 border-b border-line px-4 py-3.5 last:border-b-0">
      <span className="pt-1.5 text-sm">{label}</span>
      <div className="min-w-0">{children}</div>
    </div>
  )
}

function Checkbox({ checked, onChange, label }) {
  return (
    <span className="relative inline-grid size-4 shrink-0 place-items-center align-middle">
      <input
        type="checkbox"
        aria-label={label}
        checked={checked}
        onChange={onChange}
        className="peer size-4 cursor-pointer appearance-none rounded-[3px] border border-grey/50 bg-white checked:border-navy checked:bg-navy"
      />
      <Check size={12} strokeWidth={3} className="pointer-events-none absolute hidden text-white peer-checked:block" />
    </span>
  )
}

export default function Config({ config, dirty, error, onChange, onReset, onSave }) {
  const { models: MODELS, sensitivityLevels: SENSITIVITY, dataAccess: DATA_ACCESS, piiTags, piiLabels } = useMeta()
  const [showKey, setShowKey] = useState(false)
  const set = (key, value) => onChange({ ...config, [key]: value })

  const AREA_IDS = DATA_ACCESS.map((a) => a.id)
  const PII_IDS = piiTags

  // `sensitivity` is null when the threshold matches no level; the slider then sits on the nearest one.
  const distance = (l) => Math.abs(l.threshold - config.piiThreshold)
  const found = SENSITIVITY.findIndex((l) => l.id === config.sensitivity)
  const index = found >= 0 ? found : SENSITIVITY.indexOf(SENSITIVITY.reduce((a, b) => (distance(b) < distance(a) ? b : a)))
  const level = SENSITIVITY[index]

  function setProvider(provider) {
    // Keep the model valid for the provider just picked.
    const model = MODELS.find((m) => m.provider === provider).id
    onChange({ ...config, provider, model })
  }

  const updateRole = (id, change) => set('roles', config.roles.map((r) => (r.id === id ? { ...r, ...change } : r)))

  return (
    <div className="h-full overflow-auto">
      <div className="mx-auto max-w-6xl space-y-7 px-6 py-5">
        <Section title="Model">
          <Row label="Provider">
            <div role="radiogroup" aria-label="Provider" className="flex gap-1">
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  role="radio"
                  aria-checked={config.provider === p.id}
                  onClick={() => setProvider(p.id)}
                  className={`rounded-md px-2.5 py-1.5 text-sm transition-colors duration-200 ${
                    config.provider === p.id ? 'bg-blue-light text-ink' : 'text-grey hover:bg-page hover:text-ink'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </Row>
          {config.provider === 'openrouter' && (
            <Row label="API key">
              <div className="relative">
                <input
                  type={showKey ? 'text' : 'password'}
                  value={config.apiKey}
                  placeholder={config.apiKeySet ? `Saved key ending in ${config.apiKeyHint}` : ''}
                  onChange={(e) => set('apiKey', e.target.value)}
                  aria-label="OpenRouter API key"
                  spellCheck={false}
                  autoComplete="off"
                  className={`${field} w-full pl-2.5 pr-9`}
                />
                <button
                  type="button"
                  aria-label={showKey ? 'Hide key' : 'Show key'}
                  onClick={() => setShowKey((s) => !s)}
                  className="absolute right-1 top-1/2 grid size-7 -translate-y-1/2 place-items-center rounded-md text-grey hover:bg-page hover:text-ink"
                >
                  {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </Row>
          )}
          <Row label="Model">
            <Dropdown
              variant="field"
              label="Model"
              trigger={
                <>
                  {MODELS.find((m) => m.id === config.model)?.label ?? config.model}
                  <ChevronDown size={16} className="text-grey" />
                </>
              }
            >
              {(close) => (
                <ul className="p-1.5">
                  {MODELS.filter((m) => m.provider === config.provider).map((m) => (
                    <li key={m.id}>
                      <button
                        onClick={() => {
                          set('model', m.id)
                          close()
                        }}
                        className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-sm hover:bg-page"
                      >
                        {m.label}
                        {m.id === config.model && <Check size={16} className="text-navy" />}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Dropdown>
          </Row>
        </Section>

        <Section title="Security">
          <Row label="PII sensitivity">
            <div className="pt-2">
              <input
                type="range"
                min={0}
                max={SENSITIVITY.length - 1}
                step={1}
                value={index}
                onChange={(e) => {
                  const next = SENSITIVITY[Number(e.target.value)]
                  onChange({ ...config, sensitivity: next.id, piiThreshold: next.threshold })
                }}
                aria-label="PII sensitivity"
                aria-valuetext={level.label}
                className="block h-4 w-full cursor-pointer appearance-none bg-transparent [&::-moz-range-thumb]:size-4 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:border-2 [&::-moz-range-thumb]:border-white [&::-moz-range-thumb]:bg-navy [&::-moz-range-track]:h-1 [&::-moz-range-track]:rounded-md [&::-moz-range-track]:bg-blue-light/60 [&::-webkit-slider-runnable-track]:h-1 [&::-webkit-slider-runnable-track]:rounded-md [&::-webkit-slider-runnable-track]:bg-blue-light/60 [&::-webkit-slider-thumb]:-mt-1.5 [&::-webkit-slider-thumb]:size-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-white [&::-webkit-slider-thumb]:bg-navy"
              />
              <div className="mt-1.5 flex justify-between text-[13px]">
                {SENSITIVITY.map((s, i) => (
                  <span key={s.id} className={i === index ? 'text-ink' : 'text-grey'}>
                    {s.label}
                  </span>
                ))}
              </div>
              <p className="mt-2 text-sm text-grey">{SENSITIVITY_HINTS[level.id]}</p>
            </div>
          </Row>
          <Row label="Prompt guard">
            <div role="radiogroup" aria-label="Prompt guard" className="space-y-2 pt-1">
              {GUARD_MODES.map((m) => (
                <label key={m.id} className="relative flex cursor-pointer gap-2.5">
                  <input
                    type="radio"
                    name="guard-mode"
                    checked={config.guardMode === m.id}
                    onChange={() => set('guardMode', m.id)}
                    className="peer sr-only"
                  />
                  <span className="mt-0.5 grid size-4 shrink-0 place-items-center rounded-full border border-grey/50 transition-colors duration-200 peer-checked:border-navy peer-checked:bg-navy peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-blue [&>span]:opacity-0 peer-checked:[&>span]:opacity-100">
                    <span className="size-1.5 rounded-full bg-white transition-opacity duration-200" />
                  </span>
                  <span className="text-sm leading-tight">
                    <span className="block">{m.label}</span>
                    <span className="block text-grey">{m.hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </Row>
          <Row label="Mask PII in chat">
            <label className="flex cursor-pointer items-center gap-3 pt-1">
              <input
                type="checkbox"
                role="switch"
                checked={config.maskPii}
                onChange={(e) => set('maskPii', e.target.checked)}
                aria-label="Mask PII in chat"
                className="relative h-5 w-9 shrink-0 cursor-pointer appearance-none rounded-full bg-line transition-colors before:absolute before:left-0.5 before:top-0.5 before:size-4 before:rounded-full before:bg-white before:transition-transform checked:bg-navy checked:before:translate-x-4"
              />
              <span className="text-sm text-grey">
                {config.maskPii
                  ? 'Detected values show as tags, such as Email'
                  : 'Text stays as written, values are marked in the logs'}
              </span>
            </label>
          </Row>
        </Section>

        <Section title="Roles">
          {/* Fixed layout: the PII column takes whatever the fixed columns leave. */}
          <table className="w-full table-fixed border-separate border-spacing-0 text-sm">
            <colgroup>
              <col className="w-40" />
              {DATA_ACCESS.map((a) => (
                <col key={a.id} className="w-20" />
              ))}
              <col />
            </colgroup>
            <thead className="[&_th]:border-b [&_th]:border-line [&_th]:py-2 [&_th]:align-bottom [&_th]:text-[13px] [&_th]:font-normal [&_th]:leading-tight [&_th]:text-grey">
              <tr>
                <th className="pl-4 pr-2.5 text-left">Role</th>
                {DATA_ACCESS.map((a) => (
                  <th key={a.id} className="px-3 text-center">
                    {a.label}
                  </th>
                ))}
                <th className="pl-4 pr-4 text-left">Allowed PII</th>
              </tr>
            </thead>
            <tbody className="[&_tr:last-child_td]:border-b-0">
              {config.roles.map((r, i) => (
                <tr key={r.id} className="hover:bg-page">
                  <td className="border-b border-line py-2 pl-4 pr-2.5">{r.label}</td>
                  {DATA_ACCESS.map((a) => (
                    <td key={a.id} className="border-b border-line px-3 py-2 text-center">
                      <Checkbox
                        label={`${r.label}: ${a.label}`}
                        checked={r.access.includes(a.id)}
                        onChange={() => updateRole(r.id, { access: toggle(r.access, a.id, AREA_IDS) })}
                      />
                    </td>
                  ))}
                  <td className="border-b border-line py-1 pl-2 pr-4">
                    <Dropdown
                      variant="cell"
                      // Bottom rows open upwards so the panel stays inside the card.
                      placement={i >= config.roles.length - 3 ? 'up' : 'down'}
                      label={`Allowed PII for ${r.label}`}
                      trigger={
                        <>
                          <span className={r.pii.length ? '' : 'text-grey'}>
                            {r.pii.length ? r.pii.map((tag) => piiLabels[tag] ?? tag).join(', ') : 'None'}
                          </span>
                          <ChevronDown size={14} className="mt-[3px] shrink-0 text-grey" />
                        </>
                      }
                    >
                      {() => (
                        <ul className="p-1.5">
                          {PII_IDS.map((tag) => (
                            <li key={tag}>
                              <label className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-page">
                                <Checkbox
                                  checked={r.pii.includes(tag)}
                                  onChange={() => updateRole(r.id, { pii: toggle(r.pii, tag, PII_IDS) })}
                                />
                                {piiLabels[tag] ?? tag}
                              </label>
                            </li>
                          ))}
                        </ul>
                      )}
                    </Dropdown>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <div className="flex items-center justify-end gap-2">
          {error && <p className="mr-auto text-sm text-red-text">{error}</p>}
          <Button onClick={onReset}>Reset to defaults</Button>
          <Button variant="primary" disabled={!dirty} onClick={onSave}>
            Save changes
          </Button>
        </div>
      </div>
    </div>
  )
}
