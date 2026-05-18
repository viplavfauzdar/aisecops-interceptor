interface DecisionBadgeProps {
  decision: string
  size?: 'sm' | 'lg'
}

const DECISION_STYLES: Record<string, string> = {
  allow: 'bg-green-950 text-green-400 border-green-800',
  allowed: 'bg-green-950 text-green-400 border-green-800',
  block: 'bg-red-950 text-red-400 border-red-800',
  blocked: 'bg-red-950 text-red-400 border-red-800',
  require_approval: 'bg-amber-950 text-amber-400 border-amber-800',
  pending: 'bg-slate-800 text-slate-400 border-slate-700',
  dry_run: 'bg-blue-950 text-blue-400 border-blue-800',
}

const DECISION_LABELS: Record<string, string> = {
  allow: 'ALLOW',
  allowed: 'ALLOW',
  block: 'BLOCK',
  blocked: 'BLOCK',
  require_approval: 'APPROVAL',
  pending: 'PENDING',
  dry_run: 'DRY RUN',
}

export function DecisionBadge({ decision, size = 'sm' }: DecisionBadgeProps) {
  const key = decision?.toLowerCase() ?? ''
  const styles = DECISION_STYLES[key] ?? 'bg-slate-800 text-slate-400 border-slate-700'
  const label = DECISION_LABELS[key] ?? decision?.toUpperCase()

  const sizeClasses = size === 'lg'
    ? 'px-3 py-1 text-sm'
    : 'px-2 py-0.5 text-xs'

  return (
    <span
      className={`inline-block font-mono font-semibold tracking-tight border rounded ${sizeClasses} ${styles}`}
    >
      {label}
    </span>
  )
}
