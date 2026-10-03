import { Check, ChevronDown } from 'lucide-react'
import Avatar from '../ui/Avatar'
import BudgetBar from '../ui/BudgetBar'
import Dropdown from '../ui/Dropdown'

export default function UserMenu({ people, roleId, account, disabled, onSwitch, onResetBudget }) {
  const current = people.find((p) => p.id === roleId)

  return (
    <Dropdown
      label="Switch user"
      trigger={
        <>
          <Avatar name={current.user} />
          <span className="text-left leading-tight">
            <span className="block">{current.user}</span>
            <span className="block text-[13px] text-grey">{current.label}</span>
          </span>
          <ChevronDown size={16} className="text-grey" />
        </>
      }
    >
      {(close) => (
        <>
          <div className="border-b border-line px-3.5 py-3">
            <BudgetBar {...account} />
            <div className="mt-2 flex justify-end gap-3 text-[13px] text-grey">
              <button disabled={disabled} onClick={() => onResetBudget(roleId)} className="hover:text-ink disabled:opacity-50">
                Reset usage
              </button>
              <button disabled={disabled} onClick={() => onResetBudget(null)} className="hover:text-ink disabled:opacity-50">
                Reset all
              </button>
            </div>
          </div>
          <ul className="p-1.5">
            {people.map((p) => (
              <li key={p.id}>
                <button
                  disabled={disabled}
                  onClick={() => {
                    if (p.id !== roleId) onSwitch(p.id)
                    close()
                  }}
                  className="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-page disabled:opacity-50"
                >
                  <Avatar name={p.user} />
                  <span className="flex-1 leading-tight">
                    <span className="block">{p.user}</span>
                    <span className="block text-[13px] text-grey">{p.label}</span>
                  </span>
                  {p.id === roleId && <Check size={16} className="text-navy" />}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </Dropdown>
  )
}
