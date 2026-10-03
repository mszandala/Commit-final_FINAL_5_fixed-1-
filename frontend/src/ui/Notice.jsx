const TONES = {
  grey: 'text-grey',
  amber: 'text-amber-text',
  red: 'text-red-text',
}

export default function Notice({ icon: Icon, tone = 'grey', title, children }) {
  return (
    <div className="flex gap-2.5 text-sm">
      <Icon size={16} className={`mt-0.5 shrink-0 ${TONES[tone]}`} />
      <div className="space-y-0.5">
        <p className={TONES[tone]}>{title}</p>
        {children}
      </div>
    </div>
  )
}
