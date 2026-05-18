import { DecisionBadge } from './DecisionBadge'

interface MetadataTooltipProps {
  eventId: string
  timestamp?: string
  decision: string
  eventType: string
  provenanceSummary: string
}

export function MetadataTooltip({
  eventId,
  timestamp,
  decision,
  eventType,
  provenanceSummary,
}: MetadataTooltipProps) {
  return (
    <div
      className={[
        'absolute bottom-full left-0 mb-1 z-50',
        'hidden group-hover:block',
        'bg-slate-900 border border-slate-700 rounded-sm p-2',
        'w-64 text-xs font-mono text-slate-300 shadow-lg',
      ].join(' ')}
    >
      <p className="text-slate-500 mb-0.5">event_id</p>
      <p className="text-slate-200 mb-2 break-all">{eventId || '—'}</p>

      <p className="text-slate-500 mb-0.5">timestamp</p>
      <p className="text-slate-200 mb-2">{timestamp ?? '—'}</p>

      <p className="text-slate-500 mb-0.5">decision</p>
      <div className="mb-2">
        <DecisionBadge decision={decision} />
      </div>

      <p className="text-slate-500 mb-0.5">event_type</p>
      <p className="text-slate-200 mb-2">{eventType}</p>

      {provenanceSummary && (
        <>
          <p className="text-slate-500 mb-0.5">provenance</p>
          <p className="text-slate-300 break-words">{provenanceSummary}</p>
        </>
      )}
    </div>
  )
}
