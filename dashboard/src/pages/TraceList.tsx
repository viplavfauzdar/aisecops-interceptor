import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { fetchTraces, type TraceFilters, type TraceListItem } from '../api/replayClient'
import { DecisionBadge } from '../components/DecisionBadge'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString()
}

function formatTrustSummary(trust: Record<string, number>): string {
  return Object.entries(trust)
    .map(([level, count]) => `${level}:${count}`)
    .join(' ') || '—'
}

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}


export function TraceList() {
  const [decisionFilter, setDecisionFilter] = useState('')
  const [toolFilter, setToolFilter] = useState('')
  const [provenanceFilter, setProvenanceFilter] = useState('')

  const debouncedTool = useDebounce(toolFilter, 300)
  const debouncedProvenance = useDebounce(provenanceFilter, 300)

  const filters: TraceFilters = {}
  if (decisionFilter) filters.decision = decisionFilter
  if (debouncedTool) filters.tool_name = debouncedTool
  if (debouncedProvenance) filters.provenance_trust = debouncedProvenance

  const { data, isLoading, isError, refetch } = useQuery<TraceListItem[]>({
    queryKey: ['traces', filters],
    queryFn: () => fetchTraces(filters),
    retry: 1,
  })

  return (
    <div className="flex flex-col min-h-0">
      {/* Filter bar */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800 bg-slate-900 flex-wrap">
        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono rounded px-2 py-1.5 focus:outline-none focus:border-slate-500"
        >
          <option value="">All decisions</option>
          <option value="allow">allow</option>
          <option value="allowed">allowed</option>
          <option value="block">block</option>
          <option value="blocked">blocked</option>
          <option value="require_approval">require_approval</option>
          <option value="pending">pending</option>
          <option value="dry_run">dry_run</option>
        </select>

        <input
          type="text"
          placeholder="Filter by tool name…"
          value={toolFilter}
          onChange={(e) => setToolFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono rounded px-2 py-1.5 focus:outline-none focus:border-slate-500 w-44"
        />

        <input
          type="text"
          placeholder="Filter by provenance trust…"
          value={provenanceFilter}
          onChange={(e) => setProvenanceFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono rounded px-2 py-1.5 focus:outline-none focus:border-slate-500 w-52"
        />

        <button
          onClick={() => refetch()}
          className="ml-auto flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors px-2 py-1.5"
        >
          <RefreshCw size={12} />
          Refresh
        </button>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {isError && (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <p className="text-red-400 text-sm font-mono">
              Backend unavailable. Check that the API is running at {API_BASE}.
            </p>
            <button
              onClick={() => refetch()}
              className="text-xs text-slate-400 hover:text-slate-200 underline"
            >
              Retry
            </button>
          </div>
        )}

        {!isError && (
          <table className="w-full text-xs font-mono border-collapse">
            <thead className="sticky top-0 bg-slate-950 z-10">
              <tr className="border-b border-slate-800 text-left">
                <th className="px-3 py-2 text-slate-400 font-medium">Trace ID</th>
                <th className="px-3 py-2 text-slate-400 font-medium">Decision</th>
                <th className="px-3 py-2 text-slate-400 font-medium">Tool</th>
                <th className="px-3 py-2 text-slate-400 font-medium text-right">Events</th>
                <th className="px-3 py-2 text-slate-400 font-medium">First Seen</th>
                <th className="px-3 py-2 text-slate-400 font-medium">Last Seen</th>
                <th className="px-3 py-2 text-slate-400 font-medium">Provenance</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={7} className="px-3 py-16 text-center">
                    <p className="text-slate-500 text-sm font-mono">Loading traces...</p>
                  </td>
                </tr>
              )}

              {!isLoading && data?.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-16 text-center">
                    <p className="text-slate-500 text-sm font-mono">
                      No traces found. Adjust filters or check that the interceptor has processed events.
                    </p>
                  </td>
                </tr>
              )}

              {!isLoading && data?.map((trace) => (
                <tr
                  key={trace.trace_id}
                  className="border-b border-slate-800 hover:bg-slate-900 transition-colors"
                >
                  <td className="px-3 py-2">
                    <Link
                      to={`/trace/${trace.trace_id}`}
                      className="text-slate-200 hover:text-white underline decoration-slate-600 hover:decoration-slate-400"
                    >
                      {trace.trace_id.slice(0, 8)}…
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <DecisionBadge decision={trace.final_decision} />
                  </td>
                  <td className="px-3 py-2 text-slate-300">
                    {trace.tool_name ?? '—'}
                  </td>
                  <td className="px-3 py-2 text-slate-300 text-right">
                    {trace.event_count}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {formatDateTime(trace.first_seen)}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {formatDateTime(trace.last_seen)}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {formatTrustSummary(trace.provenance_trust_summary)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
