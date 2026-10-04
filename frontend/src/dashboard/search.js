import { parse, test } from 'liqe'

// Log search. Plain mode keeps turns that contain every typed word. Advanced mode takes a
// Datadog-style query (`role:hr -level:info tokens:>1000`), parsed by liqe. The tokenizer below
// colours the query while it is typed, and also lowercases it before parsing, so matching ignores
// case and Polish accents on both sides.
//
// Both modes return { match, matchStep }: `match(event)` keeps a turn, and `matchStep(event, step)`
// is true when the query holds with only that step's values, so the log can point at the steps
// that made a turn match.

// Lowercase and drop accents. "ł" has no decomposed form, so it is mapped by hand.
export const fold = (s) =>
  String(s ?? '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/ł/g, 'l')

const pad = (n) => String(n).padStart(2, '0')

// Every value inside a step's details, without the keys, so `details:salar` does not match "salary_cap".
const leaves = (v) =>
  v && typeof v === 'object' ? Object.values(v).flatMap(leaves) : v == null || v === '' ? [] : [fold(v)]

const LEVEL_WORDS = { info: 'ok', warn: 'warning', block: 'blocked' }

// What each field matches. Arrays match when any item does. Adding a field is one line.
const TURN_FIELDS = {
  id: (e) => e.id,
  user: (e) => fold(e.user),
  role: (e) => [fold(e.role), fold(e.roleId)],
  decision: (e) => fold(e.decision),
  level: (e) => [e.level, LEVEL_WORDS[e.level]],
  control: (e) => fold(e.control),
  reason: (e) => fold(e.reason),
  stage: (e) => fold(e.stage),
  model: (e) => fold(e.model),
  prompt: (e) => fold(e.maskedPrompt),
  masked: (e) => (e.maskedForModel ?? []).map(fold),
  hidden: (e) => e.hidden.map(fold),
  steps: (e) => e.stepCount,
  tokens: (e) => e.tokens,
  latency: (e) => e.latencyMs,
  date: (e) => `${e.time.getFullYear()}-${pad(e.time.getMonth() + 1)}-${pad(e.time.getDate())}`,
  time: (e) => e.time.toLocaleTimeString('en-GB'),
  hour: (e) => e.time.getHours(),
}
// A turn holds the values of all its steps; a single step only its own.
const STEP_FIELDS = {
  step: (s) => [fold(s.summary)],
  details: (s) => leaves(s.details),
  kind: (s, meta) => [s.kind, fold(meta.stepKinds[s.kind])],
  zone: (s) => [s.zone],
}
const FIELDS = [...Object.keys(TURN_FIELDS), ...Object.keys(STEP_FIELDS)]
// liqe matches `id:3` as a substring (3, 13, 30...); on these fields a bare number means exactly that.
const NUMBER_FIELDS = ['id', 'steps', 'tokens', 'latency', 'hour']

// Plain mode reads these, so a typed "2" does not hit every number and date.
const PLAIN_FIELDS = ['user', 'role', 'decision', 'control', 'reason', 'model', 'prompt', 'masked']

// Built once per event or step object; the store replaces the objects when the log refreshes.
// `fields` is what advanced queries see, `text` what plain mode looks through.
const cache = new WeakMap()
const memo = (key, build) => {
  if (!cache.has(key)) cache.set(key, build())
  return cache.get(key)
}

const stepRow = (s, meta) =>
  memo(s, () => {
    const fields = Object.fromEntries(Object.entries(STEP_FIELDS).map(([f, get]) => [f, get(s, meta)]))
    return { fields, text: Object.values(fields).flat().join(' ') }
  })

const turnRow = (e, meta) =>
  memo(e, () => {
    const fields = Object.fromEntries(Object.entries(TURN_FIELDS).map(([f, get]) => [f, get(e, meta) ?? '']))
    const own = PLAIN_FIELDS.map((f) => fields[f]).flat().join(' ')
    const steps = e.steps.map((s) => stepRow(s, meta))
    for (const f in STEP_FIELDS) fields[f] = steps.flatMap((s) => s.fields[f])
    return { fields, own, text: [own, ...steps.map((s) => s.text)].join(' ') }
  })

export function plainMatcher(query, meta) {
  const words = fold(query).split(/\s+/).filter(Boolean)
  const has = (text) => words.every((w) => text.includes(w))
  return {
    match: (e) => has(turnRow(e, meta).text),
    matchStep: (e, s) => has(`${turnRow(e, meta).own} ${stepRow(s, meta).text}`),
  }
}

// Order matters: a field is a word followed by a colon, so it is tried before plain words.
const TOKEN = new RegExp(
  [
    /(?<space>\s+)/,
    /(?<quoted>"(?:[^"\\]|\\.)*"?)/,
    /(?<paren>[()])/,
    /(?<not>-(?=[\p{L}_("]))/,
    /(?<field>[\p{L}_][\p{L}\d_.]*)(?<op>:(?:[<>]=?|=)?)/,
    /(?<range>\[[^\]]*\]?)/,
    /(?<regex>\/(?:[^/\\]|\\.)*\/?)/,
    /(?<word>[^\s()"]+)/,
  ]
    .map((r) => r.source)
    .join('|'),
  'gu',
)

// Splits the query into coloured pieces. Never fails, so half-typed queries still get colour.
// Kinds: space, paren, field, unknown (field), op, value, number, quoted, range, regex, bool, not.
export function tokenize(query) {
  const tokens = []
  let afterOp = false
  for (const m of query.matchAll(TOKEN)) {
    const g = m.groups
    if (g.field) {
      tokens.push({ kind: FIELDS.includes(fold(g.field)) ? 'field' : 'unknown', text: g.field })
      tokens.push({ kind: 'op', text: g.op })
      afterOp = true
      continue
    }
    if (g.word || (g.not && afterOp)) {
      const word = g.word ?? g.not
      const kind =
        !afterOp && /^(AND|OR|NOT)$/.test(word) ? 'bool' : /^-?\d+(\.\d+)?$/.test(word) ? 'number' : 'value'
      tokens.push({ kind, text: word })
    } else {
      const kind = Object.keys(g).find((k) => g[k] !== undefined)
      tokens.push({ kind, text: g[kind] })
    }
    afterOp = false
  }
  return tokens
}

// Every `field:value` in the query.
const tags = (ast) =>
  !ast
    ? []
    : ast.type === 'Tag'
      ? [ast]
      : [ast.left, ast.right, ast.operand, ast.expression].flatMap(tags)

// liqe accepts any field name and an empty value, and then quietly matches nothing.
function check(tag) {
  if (tag.field.type !== 'Field') return null
  if (!FIELDS.includes(tag.field.name)) return `Unknown field "${tag.field.name}"`
  if (tag.expression.type === 'EmptyExpression') return `Add a value after "${tag.field.name}:"`
  return null
}

// liqe reads `-` only before a field or a word, so it is passed on as NOT, which also takes `-(a OR b)`.
const forLiqe = (t) => (t.kind === 'not' ? 'NOT ' : t.kind === 'bool' || t.kind === 'range' ? t.text : fold(t.text))

// Returns { match, matchStep } or { error }.
export function advancedMatcher(query, meta) {
  const tokens = tokenize(query)
  if (tokens.every((t) => t.kind === 'space')) return plainMatcher('', meta)
  let ast
  try {
    ast = parse(tokens.map(forLiqe).join(''))
  } catch {
    return { error: 'Cannot parse this query' }
  }
  const all = tags(ast)
  const error = all.map(check).find(Boolean)
  if (error) return { error }
  for (const tag of all) {
    const exact = NUMBER_FIELDS.includes(tag.field.name) && typeof tag.expression.value === 'number'
    if (exact && tag.operator.operator === ':') tag.operator.operator = ':='
  }
  return {
    match: (e) => test(ast, turnRow(e, meta).fields),
    matchStep: (e, s) => test(ast, { ...turnRow(e, meta).fields, ...stepRow(s, meta).fields }),
  }
}
