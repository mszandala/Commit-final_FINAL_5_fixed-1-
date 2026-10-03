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

export const DATA_ACCESS = [
  { id: 'projects', label: 'Projects' },
  { id: 'hr', label: 'HR data' },
  { id: 'clients', label: 'Bank clients' },
  { id: 'markets', label: 'Markets and reports' },
  { id: 'code', label: 'Run code' },
]

export const PII_TAGS = {
  NAME: 'Name',
  SALARY: 'Salary',
  EMAIL: 'Email',
  'PHONE-NO': 'Phone',
  'CREDIT-CARD-NO': 'Card number',
  PASSWORD: 'Password',
  PROJECT: 'Project',
}

const role = (id, label, access, pii = []) => ({ id, label, access, pii })

const config = {
  provider: 'openrouter',
  apiKey: 'sk-or-v1-example-key',
  model: 'google/gemma-4-26b-a4b-it',
  sensitivity: 1,
  guardMode: 'warn',
  maskPii: true,
  roles: [
    role('basic', 'Basic user', ['projects']),
    role('hr', 'HR', ['projects', 'hr'], ['NAME', 'SALARY']),
    role('banker', 'Banker', ['projects', 'clients'], ['NAME', 'EMAIL', 'PHONE-NO']),
    role('analyst', 'Analyst', ['projects', 'clients', 'markets']),
    role('lawyer', 'Lawyer', ['projects', 'markets']),
    role('portfolio', 'Portfolio manager', ['projects', 'markets']),
    role('it', 'IT', ['projects', 'code'], ['PASSWORD', 'PROJECT']),
    role(
      'admin',
      'Admin',
      ['projects', 'hr', 'clients', 'markets', 'code'],
      ['NAME', 'SALARY', 'EMAIL', 'PHONE-NO', 'CREDIT-CARD-NO', 'PASSWORD'],
    ),
  ],
}

export function getConfig() {
  return config
}
