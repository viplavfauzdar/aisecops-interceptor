interface ProvenanceBadgeProps {
  entries: unknown
  maxVisible?: number
}

const SOURCE_LABELS: Record<string, string> = {
  user_prompt: 'USER',
  system_prompt: 'SYS',
  skill: 'SKILL',
  retrieval_chunk: 'RAG',
  memory: 'MEM',
  tool_result: 'TOOL',
  agent_message: 'AGENT',
}

const TRUST_STYLES: Record<string, string> = {
  trusted: 'bg-green-900 text-green-300 border-green-700',
  internal: 'bg-blue-900 text-blue-300 border-blue-700',
  external: 'bg-amber-900 text-amber-300 border-amber-700',
  unverified: 'bg-red-900 text-red-300 border-red-700',
}

type NormalizedEntry = { source: string; trust: string }

function normalize(raw: unknown): NormalizedEntry[] {
  if (Array.isArray(raw)) {
    return (raw as Record<string, unknown>[]).map((entry) => ({
      source: String(entry.source_type ?? entry.source ?? ''),
      trust: String(entry.trust_level ?? entry.trust ?? ''),
    }))
  }
  if (raw && typeof raw === 'object') {
    return Object.entries(raw as Record<string, unknown>).map(([key, val]) => ({
      source: key,
      trust: typeof val === 'string' ? val : 'unknown',
    }))
  }
  return []
}

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source.slice(0, 6).toUpperCase()
}

const BADGE = 'font-mono text-xs px-1.5 py-0.5 border rounded-sm uppercase'
const SOURCE_BASE = 'bg-slate-800 text-slate-300 border-slate-600'
const TRUST_BASE = 'bg-slate-800 text-slate-500 border-slate-600'

export function ProvenanceBadge({ entries, maxVisible = 4 }: ProvenanceBadgeProps) {
  const normalized = normalize(entries)
  if (!normalized.length) return null

  const visible = normalized.slice(0, maxVisible)
  const overflow = normalized.length - visible.length

  return (
    <div className="flex items-center gap-1 flex-wrap">
      {visible.map((entry, i) => (
        <span key={i} className="inline-flex">
          <span className={`${BADGE} ${SOURCE_BASE}`}>{sourceLabel(entry.source)}</span>
          <span className={`${BADGE} ${TRUST_STYLES[entry.trust] ?? TRUST_BASE}`}>
            {entry.trust || '?'}
          </span>
        </span>
      ))}
      {overflow > 0 && (
        <span className="font-mono text-xs text-slate-500">+{overflow} more</span>
      )}
    </div>
  )
}
