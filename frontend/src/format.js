// 12450 -> "12 450", with a narrow no-break space
export const formatNumber = (n) =>
  Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '\u202f')

// 0.00048 -> "$0.0005", 0.5 -> "$0.50": per-turn costs are fractions of a cent, limits are not
export const formatUsd = (n) => `$${n >= 0.01 || n === 0 ? n.toFixed(2) : n.toFixed(4)}`
