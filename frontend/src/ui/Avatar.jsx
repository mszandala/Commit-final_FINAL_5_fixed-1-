export default function Avatar({ name }) {
  const initials = name
    .split(' ')
    .map((part) => part[0])
    .join('')

  return (
    <span className="grid size-8 shrink-0 place-items-center rounded-md bg-blue-light text-[13px] font-semibold text-ink">
      {initials}
    </span>
  )
}
