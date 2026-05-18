import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, RefreshCw, Copy } from 'lucide-react'
import { fetchTrace, fetchTraceSummary, type TraceEvent } from '../api/replayClient'
import { EventDrawer } from '../components/EventDrawer'
import { ExecutionGraph } from '../components/ExecutionGraph'
import { SummaryCards } from '../components/SummaryCards'
import { TimelineEvent } from '../components/TimelineEvent'
import { copyToClipboard } from '../lib/clipboard'

type Tab = 'timeline' | 'graph'

const TABS: Tab[] = ['timeline', 'graph']

export function TraceDetail() {
  const { traceId } = useParams<{ traceId: string }>()
  const [selectedEvent, setSelectedEvent] = useState<TraceEvent | null>(null)
  const [activeTab, setActiveTab] = useState<Tab>('timeline')

  const traceQuery = useQuery({
    queryKey: ['trace', traceId],
    queryFn: () => fetchTrace(traceId!),
    enabled: !!traceId,
    retry: 1,
  })

  const summaryQuery = useQuery({
    queryKey: ['trace-summary', traceId],
    queryFn: () => fetchTraceSummary(traceId!),
    enabled: !!traceId,
    retry: 1,
  })

  const isLoading = traceQuery.isLoading || summaryQuery.isLoading
  const isError = traceQuery.isError || summaryQuery.isError

  return (
    <div className="flex flex-col min-h-0">
      {/* Sub-nav */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800 bg-slate-900">
        <Link
          to="/"
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft size={12} />
          Traces
        </Link>
        <span className="text-slate-700">/</span>
        <span className="font-mono text-xs text-slate-300 truncate max-w-xs">
          {traceId?.slice(0, 16)}
        </span>
        {traceId && (
          <button
            onClick={() => copyToClipboard(traceId)}
            className="text-slate-600 hover:text-slate-400 transition-colors"
            title="Copy full trace ID"
          >
            <Copy size={12} />
          </button>
        )}
        <button
          onClick={() => { traceQuery.refetch(); summaryQuery.refetch() }}
          className="ml-auto flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RefreshCw size={12} />
          Refresh
        </button>
      </div>

      <div className="flex-1 overflow-auto p-4">
        {isError && (
          <div className="flex flex-col items-center py-20 gap-3">
            <p className="text-red-400 text-sm font-mono">
              Trace not found or backend error.
            </p>
            <Link to="/" className="text-xs text-slate-400 hover:text-slate-200 underline">
              Back to traces
            </Link>
          </div>
        )}

        {isLoading && (
          <p className="text-slate-500 text-sm font-mono text-center py-20">
            Loading trace {traceId}…
          </p>
        )}

        {!isLoading && !isError && traceQuery.data && summaryQuery.data && (
          <SummaryCards trace={traceQuery.data} summary={summaryQuery.data} />
        )}

        {!isLoading && !isError && traceQuery.data && (
          <>
            {/* Tab bar */}
            <div className="flex gap-0 border-b border-slate-800 mb-4">
              {TABS.map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={[
                    'px-4 py-2 text-xs font-mono uppercase tracking-wider border-b-2 -mb-px',
                    activeTab === tab
                      ? 'border-slate-300 text-slate-100'
                      : 'border-transparent text-slate-500 hover:text-slate-300',
                  ].join(' ')}
                >
                  {tab}
                </button>
              ))}
            </div>

            {activeTab === 'timeline' && (
              <div>
                {traceQuery.data.timeline.map((event, idx) => (
                  <TimelineEvent
                    key={event.event_id ?? idx}
                    event={event}
                    isLast={idx === traceQuery.data!.timeline.length - 1}
                    onSelect={setSelectedEvent}
                  />
                ))}
              </div>
            )}

            {activeTab === 'graph' && (
              <ExecutionGraph
                events={traceQuery.data.timeline}
                onNodeClick={(eventId) => {
                  const ev = traceQuery.data!.timeline.find(e => e.event_id === eventId)
                  if (ev) setSelectedEvent(ev)
                }}
              />
            )}
          </>
        )}
      </div>

      <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  )
}
