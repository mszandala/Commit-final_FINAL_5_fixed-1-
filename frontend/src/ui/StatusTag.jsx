const DOTS = {
  Allowed: 'bg-green',
  Redacted: 'bg-amber',
  Blocked: 'bg-red',
}

export default function StatusTag({ status }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`size-2 rounded-full ${DOTS[status]}`} />
      {status}
    </span>
  )
}
