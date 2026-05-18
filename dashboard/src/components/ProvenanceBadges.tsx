import type { ProvenanceEntry } from '../api/replayClient'

type ProvenanceInput = ProvenanceEntry[] | Record<string, unknown> | undefined

interface Props {
  provenance: ProvenanceInput
}

const SOURCE_STYLES: Record<string, string> = {
  user_prompt: 'bg-slate-700 text-slate-200',
  system_prompt: 'bg-slate-700 text-slate-200',
  skill: 'bg-indigo-900 text-indigo-300',
  retrieval_chunk: 'bg-cyan-900 text-cyan-300',
  memory: 'bg-violet-900 text-violet-300',
  tool_result: 'bg-teal-900 text-teal-300',
  agent_message: 'bg-sky-900 text-sky-300',
}

const TRUST_STYLES: Record<string, string> = {
  trusted: 'border-l-2 border-green-500 text-green-400',
  internal: 'border-l-2 border-blue-500 text-blue-400',
  external: 'border-l-2 border-amber-500 text-amber-400',
  unverified: 'border-l-2 border-red-500 text-red-400',
}

type NormalizedEntry = { source: string; trust: string }

function normalize(provenance: ProvenanceInput): NormalizedEntry[] {
  if (!provenance) return []
  if (Array.isArray(provenance)) {
    return provenance.map((p) => ({
      source: String(p.source_type ?? (p as Record<string, unknown>).source ?? ''),
      trust: String(p.trust_level ?? (p as Record<string, unknown>).trust ?? ''),
    }))
  }
  // plain object — try to extract a single entry
  const src = String(provenance.source_type ?? provenance.source ?? '')
  const trust = String(provenance.trust_level ?? provenance.trust ?? '')
  return src || trust ? [{ source: src, trust }] : []
}

export function ProvenanceBadges({ provenance }: Props) {
  const entries = normalize(provenance)
  if (!entries.length) return null

  const visible = entries.slice(0, 4)
  const overflow = entries.length - visible.length

  return (
    <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
      {visible.map((entry, i) => (
        <span key={i} className="flex items-center gap-1">
          <span className={`font-mono text-xs px-1.5 py-0.5 rounded-sm ${SOURCE_STYLES[entry.source] ?? 'bg-slate-800 text-slate-400'}`}>
            {entry.source || '?'}
          </span>
          {entry.trust && (
            <span className={`font-mono text-xs px-1.5 py-0.5 bg-slate-900 ${TRUST_STYLES[entry.trust] ?? 'border-l-2 border-slate-600 text-slate-500'}`}>
              {entry.trust}
            </span>
          )}
        </span>
      ))}
      {overflow > 0 && (
        <span className="font-mono text-xs text-slate-500">+{overflow} more</span>
      )}
    </div>
  )
}
