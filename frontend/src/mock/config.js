export const MODELS = [
  { id: 'google/gemma-4-26b-a4b-it', label: 'Gemma 4 26B', provider: 'openrouter' },
  { id: 'google/gemma-4-26b-a4b-it:free', label: 'Gemma 4 26B, free tier', provider: 'openrouter' },
  { id: 'gemma4:12b', label: 'Gemma 4 12B', provider: 'ollama' },
]

export const SENSITIVITY = [
  { label: 'Low', threshold: 0.5, hint: 'Flags only clear-cut matches, fewer false alarms' },
  { label: 'Balanced', threshold: 0.35, hint: 'Recommended for everyday use' },
  { label: 'High', threshold: 0.2, hint: 'Flags anything that looks like personal data' },
]

// Groups of backend tools, as in backend/config.py. Generic file tools are admin-only and not shown.
export const DATA_ACCESS = [
  { id: 'projects', label: 'Projects', tools: ['list_projects', 'read_project'] },
  { id: 'hr', label: 'HR data', tools: ['read_employee_records'] },
  { id: 'clients', label: 'Bank clients', tools: ['read_client_records'] },
  { id: 'campaigns', label: 'Campaigns', tools: ['read_bank_campaigns'] },
  { id: 'stocks', label: 'Stock prices', tools: ['read_stock_prices'] },
  { id: 'earnings', label: 'Earnings calls', tools: ['list_earnings_calls', 'read_earnings_call'] },
  { id: 'code', label: 'Run code', tools: ['run_python'] },
  { id: 'subagents', label: 'Subagents', tools: ['create_subagent'] },
]

// Per-role PII. Email and phone numbers are always masked and passwords and card numbers
// always blocked, whatever the role (GLOBAL_REDACTED_PII and GLOBAL_BLOCKED_PII).
export const PII_TAGS = {
  NAME: 'Name',
  SALARY: 'Salary',
  ORGANIZATION: 'Organization',
  LOCATION: 'Location',
  PROJECT: 'Project',
}

export const REDACTED_PII = {
  EMAIL: 'Email',
  'PHONE-NO': 'Phone',
}

// Backend verdict stages, by the name people see.
export const CONTROLS = {
  prompt_guard: 'Prompt guard',
  tool_whitelist: 'Tool permissions',
  pii_policy: 'PII policy',
  code_guard: 'Code guard',
  budget: 'Token budget',
}

const role = (id, label, access, pii) => ({ id, label, access, pii })

// Ids match the role aliases the backend's prompt guard accepts.
const config = {
  provider: 'openrouter',
  apiKey: 'sk-or-v1-example-key',
  model: 'google/gemma-4-26b-a4b-it',
  sensitivity: 1,
  guardMode: 'block',
  maskPii: true,
  roles: [
    role('basic_user', 'Employee', ['projects'], ['ORGANIZATION', 'PROJECT']),
    role('hr', 'HR', ['projects', 'hr'], ['SALARY', 'ORGANIZATION', 'PROJECT']),
    role('banker', 'Banker', ['projects', 'clients', 'campaigns'], ['SALARY', 'ORGANIZATION', 'LOCATION', 'PROJECT']),
    role(
      'analyst',
      'Analyst',
      ['projects', 'campaigns', 'stocks', 'earnings', 'subagents'],
      ['SALARY', 'ORGANIZATION', 'LOCATION', 'PROJECT'],
    ),
    role('lawyer', 'Lawyer', ['projects', 'earnings'], ['NAME', 'ORGANIZATION', 'LOCATION', 'PROJECT']),
    role(
      'portfolio_manager',
      'Portfolio manager',
      ['projects', 'stocks', 'earnings'],
      ['NAME', 'SALARY', 'ORGANIZATION', 'LOCATION', 'PROJECT'],
    ),
    role('it', 'IT', ['projects', 'subagents'], ['ORGANIZATION', 'PROJECT']),
    role(
      'admin',
      'Admin',
      DATA_ACCESS.map((a) => a.id),
      ['NAME', 'SALARY', 'ORGANIZATION', 'LOCATION', 'PROJECT'],
    ),
  ],
}

export function getConfig() {
  return config
}
