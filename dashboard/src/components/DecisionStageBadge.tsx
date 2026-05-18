interface DecisionStageBadgeProps {
  stage: string
}

const STAGE_STYLES: Record<string, string> = {
  plan: 'bg-blue-900 text-blue-300 border-blue-700',
  evaluate: 'bg-amber-900 text-amber-300 border-amber-700',
  execute: 'bg-green-900 text-green-300 border-green-700',
  block: 'bg-red-900 text-red-300 border-red-700',
  blocked: 'bg-red-900 text-red-300 border-red-700',
  approval: 'bg-orange-900 text-orange-300 border-orange-700',
  require_approval: 'bg-orange-900 text-orange-300 border-orange-700',
  dry_run: 'bg-purple-900 text-purple-300 border-purple-700',
}

export function DecisionStageBadge({ stage }: DecisionStageBadgeProps) {
  const key = stage?.toLowerCase() ?? ''
  const styles = STAGE_STYLES[key] ?? 'bg-slate-800 text-slate-400 border-slate-600'
  return (
    <span className={`font-mono text-xs uppercase px-2 py-0.5 border rounded-sm ${styles}`}>
      {stage}
    </span>
  )
}
