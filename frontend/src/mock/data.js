// One person per role in mock/config.js, keyed by role id. Token budgets are per day.
export const USERS = {
  basic_user: { name: 'Piotr Nowak', budget: 20000, used: 16800 },
  hr: { name: 'Anna Wiśniewska', budget: 50000, used: 21340 },
  banker: { name: 'Katarzyna Wójcik', budget: 50000, used: 12610 },
  analyst: { name: 'Michał Kamiński', budget: 100000, used: 64200 },
  lawyer: { name: 'Magdalena Kowalczyk', budget: 50000, used: 8450 },
  portfolio_manager: { name: 'Jakub Szymański', budget: 100000, used: 37900 },
  it: { name: 'Tomasz Lewandowski', budget: 50000, used: 30120 },
  admin: { name: 'Marek Zieliński', budget: 200000, used: 48120 },
}
