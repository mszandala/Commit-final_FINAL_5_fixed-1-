// 12450 -> "12 450", with a narrow no-break space
export const formatNumber = (n) =>
  Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '\u202f')

export const formatSize = (bytes) =>
  bytes < 1024 * 1024 ? `${formatNumber(Math.max(1, bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`
