const DOTS = {
  Allowed: 'bg-green',
  Redacted: 'bg-amber',
  Blocked: 'bg-red',
}

export default function StatusTag({ status }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] text-ink">
      <span className={`size-1.5 rounded-full ${DOTS[status]}`} />
      {status}
    </span>
  )
}
