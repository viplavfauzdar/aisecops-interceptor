import type { TraceEvent } from '../api/replayClient'
import { copyToClipboard } from '../lib/clipboard'
import { DecisionBadge } from './DecisionBadge'
import { DecisionStageBadge } from './DecisionStageBadge'
import { ProvenanceBadges } from './ProvenanceBadges'

interface TimelineEventProps {
  event: TraceEvent
  isLast: boolean
  onSelect: (event: TraceEvent) => void
}

const STAGE_DOT: Record<string, string> = {
  plan: 'bg-blue-500',
  evaluate: 'bg-amber-500',
  execute: 'bg-green-500',
  block: 'bg-red-500',
  blocked: 'bg-red-500',
  approval: 'bg-orange-500',
  require_approval: 'bg-orange-500',
  dry_run: 'bg-purple-500',
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-US', {
    hour12: false,
    fractionalSecondDigits: 3,
  })
}

export function TimelineEvent({ event, isLast, onSelect }: TimelineEventProps) {
  const stage = event.decision_stage?.toLowerCase() ?? ''
  const dotColor = STAGE_DOT[stage] ?? 'bg-slate-600'

  return (
    <div className="relative flex">
      {/* Left connector column */}
      <div className="flex flex-col items-center flex-none w-5 pt-3">
        <div className={`w-2 h-2 rounded-full flex-none ${dotColor}`} />
        {!isLast && <div className="w-px flex-1 bg-slate-700 mt-1" />}
      </div>

      {/* Row content — entire area is the click target */}
      <button
        onClick={() => onSelect(event)}
        className="flex-1 min-w-0 text-left py-2 pr-3 pl-2 hover:bg-slate-800/50 cursor-pointer transition-colors rounded-sm"
      >
        {/* Line 1: meta row */}
        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          <span className="text-slate-500">{formatTime(event.timestamp)}</span>
          {event.decision_stage && (
            <DecisionStageBadge stage={event.decision_stage} />
          )}
          <span className="text-slate-200">{event.event_type}</span>
          {event.tool_name && (
            <span className="text-slate-400">{event.tool_name}</span>
          )}
          <DecisionBadge decision={event.decision} />
          <span
            className="ml-auto flex items-center gap-1 text-slate-600"
            title={event.event_id ?? ''}
          >
            <span>{event.event_id?.slice(0, 8) ?? '—'}</span>
            {event.event_id && (
              <span
                role="button"
                onClick={(e) => { e.stopPropagation(); copyToClipboard(event.event_id!) }}
                className="hover:text-slate-400 transition-colors cursor-pointer"
                title="Copy event ID"
              >
                📋
              </span>
            )}
          </span>
        </div>

        {/* Line 2: reason */}
        {event.reason && (
          <p className="text-xs text-slate-400 mt-1 truncate" title={event.reason}>
            {event.reason.length > 100 ? event.reason.slice(0, 100) + '…' : event.reason}
          </p>
        )}

        {/* Line 3: provenance */}
        {event.provenance?.length > 0 && (
          <ProvenanceBadges provenance={event.provenance} />
        )}
      </button>
    </div>
  )
}
