import type { ReactNode } from 'react'
import type { TraceDetail, TraceSummary } from '../api/replayClient'
import { DecisionBadge } from './DecisionBadge'

interface Props {
  trace: TraceDetail
  summary: TraceSummary
}

function formatDateTime(iso: string | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

function formatTrust(trust: Record<string, number>): string {
  return Object.entries(trust).map(([k, v]) => `${k}: ${v}`).join(', ') || '—'
}

function Card({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-sm px-4 py-3 min-w-0">
      <p className="text-xs text-slate-500 uppercase tracking-wider">{label}</p>
      <div className="text-sm text-slate-100 mt-1 truncate">{children}</div>
    </div>
  )
}

export function SummaryCards({ trace, summary }: Props) {
  const first = trace.timeline[0]?.timestamp
  const last = trace.timeline[trace.timeline.length - 1]?.timestamp

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 mb-4">
      <Card label="Final Decision">
        <DecisionBadge decision={summary.final_decision} size="lg" />
      </Card>
      <Card label="Tool">
        <span className="font-mono">{summary.tool_name ?? '—'}</span>
      </Card>
      <Card label="Events">
        <span className="font-mono">{summary.event_count}</span>
      </Card>
      <Card label="First Seen">
        <span className="font-mono text-xs">{formatDateTime(first)}</span>
      </Card>
      <Card label="Last Seen">
        <span className="font-mono text-xs">{formatDateTime(last)}</span>
      </Card>
      <Card label="Provenance">
        <span className="font-mono text-xs">{formatTrust(summary.provenance_trust_summary)}</span>
      </Card>
    </div>
  )
}
