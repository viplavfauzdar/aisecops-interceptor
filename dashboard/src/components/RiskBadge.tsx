interface RiskBadgeProps {
  riskLevel?: string | null
  size?: 'sm' | 'md'
}

const RISK_STYLES: Record<string, string> = {
  low: 'bg-slate-800 text-slate-300 border-slate-700',
  medium: 'bg-amber-950 text-amber-300 border-amber-800',
  high: 'bg-orange-950 text-orange-300 border-orange-800',
  critical: 'bg-red-950 text-red-300 border-red-800',
}

export function RiskBadge({ riskLevel, size = 'sm' }: RiskBadgeProps) {
  const key = riskLevel?.toLowerCase() ?? ''
  const styles = RISK_STYLES[key] ?? RISK_STYLES.low
  const label = key ? key.toUpperCase() : 'UNKNOWN'
  const sizeClasses = size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]'

  return (
    <span className={`inline-block font-mono font-semibold border rounded ${sizeClasses} ${styles}`}>
      {label}
    </span>
  )
}
