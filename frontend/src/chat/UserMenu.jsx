import { Check, ChevronDown } from 'lucide-react'
import { ROLES } from '../mock/data'
import Avatar from '../ui/Avatar'
import BudgetBar from '../ui/BudgetBar'
import Dropdown from '../ui/Dropdown'

export default function UserMenu({ role, account, disabled, onSwitch }) {
  const current = ROLES[role]

  return (
    <Dropdown
      label="Switch user"
      trigger={
        <>
          <Avatar name={current.name} />
          <span className="text-left leading-tight">
            <span className="block">{current.name}</span>
            <span className="block text-[13px] text-grey">{current.label}</span>
          </span>
          <ChevronDown size={16} className="text-grey" />
        </>
      }
    >
      {(close) => (
        <>
          <ul className="p-1.5">
            {Object.entries(ROLES).map(([id, r]) => (
              <li key={id}>
                <button
                  disabled={disabled}
                  onClick={() => {
                    if (id !== role) onSwitch(id)
                    close()
                  }}
                  className="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-page disabled:opacity-50"
                >
                  <Avatar name={r.name} />
                  <span className="flex-1 leading-tight">
                    <span className="block">{r.name}</span>
                    <span className="block text-[13px] text-grey">{r.label}</span>
                  </span>
                  {id === role && <Check size={16} className="text-navy" />}
                </button>
              </li>
            ))}
          </ul>
          <div className="border-t border-line px-3.5 py-3">
            <BudgetBar used={account.used} limit={account.limit} />
          </div>
        </>
      )}
    </Dropdown>
  )
}
