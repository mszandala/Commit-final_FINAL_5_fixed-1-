export default function Notice({ icon: Icon, title, children }) {
  return (
    <div className="flex gap-2.5 text-sm text-grey">
      <Icon size={16} className="mt-0.5 shrink-0" />
      <div className="space-y-0.5">
        <p className="font-semibold">{title}</p>
        {children}
      </div>
    </div>
  )
}
