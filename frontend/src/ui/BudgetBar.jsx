import { formatNumber } from '../format'

export default function BudgetBar({ used, limit }) {
  const share = used / limit
  const fill = share >= 1 ? 'bg-red' : share >= 0.8 ? 'bg-amber' : 'bg-navy'

  return (
    <div>
      <p className="text-sm">
        {formatNumber(used)} / {formatNumber(limit)} tokens
      </p>
      <div className="mt-1.5 h-1 overflow-hidden rounded-md bg-blue-light/60">
        <div className={`h-full ${fill}`} style={{ width: `${Math.min(share, 1) * 100}%` }} />
      </div>
    </div>
  )
}
