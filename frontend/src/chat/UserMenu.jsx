import { Check, ChevronDown } from 'lucide-react'
import { USERS } from '../mock/data'
import Avatar from '../ui/Avatar'
import BudgetBar from '../ui/BudgetBar'
import Dropdown from '../ui/Dropdown'

export default function UserMenu({ roles, roleId, account, disabled, onSwitch }) {
  const current = roles.find((r) => r.id === roleId)

  return (
    <Dropdown
      label="Switch user"
      trigger={
        <>
          <Avatar name={USERS[roleId].name} />
          <span className="text-left leading-tight">
            <span className="block">{USERS[roleId].name}</span>
            <span className="block text-[13px] text-grey">{current.label}</span>
          </span>
          <ChevronDown size={16} className="text-grey" />
        </>
      }
    >
      {(close) => (
        <>
          <div className="border-b border-line px-3.5 py-3">
            <BudgetBar used={account.used} limit={account.limit} />
          </div>
          <ul className="p-1.5">
            {roles.map((r) => (
              <li key={r.id}>
                <button
                  disabled={disabled}
                  onClick={() => {
                    if (r.id !== roleId) onSwitch(r.id)
                    close()
                  }}
                  className="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-page disabled:opacity-50"
                >
                  <Avatar name={USERS[r.id].name} />
                  <span className="flex-1 leading-tight">
                    <span className="block">{USERS[r.id].name}</span>
                    <span className="block text-[13px] text-grey">{r.label}</span>
                  </span>
                  {r.id === roleId && <Check size={16} className="text-navy" />}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </Dropdown>
  )
}
