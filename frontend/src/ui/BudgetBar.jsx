import { formatNumber, formatUsd } from '../format'

// A role has two limits (GET /roles budget): daily tokens and total spending in dollars.
// `share` of whichever is closer to its limit drives the warning under the composer.
export function tightestLimit({ used, limit, spent, spendingLimit }) {
  const tokens = { kind: 'tokens', share: used / limit }
  const spending = { kind: 'spending', share: spendingLimit > 0 ? spent / spendingLimit : 0 }
  return spending.share > tokens.share ? spending : tokens
}

function Bar({ share, children }) {
  const fill = share >= 1 ? 'bg-red' : share >= 0.8 ? 'bg-amber' : 'bg-navy'

  return (
    <div>
      <p className="text-sm">{children}</p>
      <div className="mt-1.5 h-1 overflow-hidden rounded-md bg-blue-light/60">
        <div className={`h-full ${fill}`} style={{ width: `${Math.min(share, 1) * 100}%` }} />
      </div>
    </div>
  )
}

export default function BudgetBar({ used, limit, spent, spendingLimit }) {
  return (
    <div className="space-y-3">
      <Bar share={used / limit}>
        {formatNumber(used)} / {formatNumber(limit)} tokens
      </Bar>
      {spendingLimit > 0 && (
        <Bar share={spent / spendingLimit}>
          {formatUsd(spent)} / {formatUsd(spendingLimit)}
        </Bar>
      )}
    </div>
  )
}
