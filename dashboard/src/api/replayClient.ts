import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

const client = axios.create({ baseURL: BASE_URL })

export type Decision = 'allow' | 'block' | 'require_approval' | 'dry_run' | 'allowed' | 'blocked' | 'pending'

export type DecisionStage =
  | 'plan'
  | 'evaluate'
  | 'execute'
  | 'block'
  | 'blocked'
  | 'approval'
  | 'require_approval'
  | 'dry_run'

export type ProvenanceSource =
  | 'user_prompt'
  | 'system_prompt'
  | 'skill'
  | 'retrieval_chunk'
  | 'memory'
  | 'tool_result'
  | 'agent_message'

export type TrustLevel = 'trusted' | 'internal' | 'external' | 'unverified'

export interface TraceFilters {
  decision?: string
  tool_name?: string
  provenance_trust?: string
}

export interface TraceListItem {
  trace_id: string
  final_decision: string
  tool_name: string
  event_count: number
  first_seen: string
  last_seen: string
  provenance_trust_summary: Record<string, number>
  final_reason?: string
  schema_versions_observed?: string[]
}

export interface ProvenanceEntry {
  source_type: string
  source_name: string
  trust_level: string
  source_hash?: string | null
  origin_uri?: string | null
  metadata?: Record<string, unknown>
  // Spec-compatible aliases
  source?: ProvenanceSource | string
  trust?: TrustLevel | string
  [key: string]: unknown
}

export interface TraceEvent {
  event_id: string | null
  schema_version: string | null
  decision_stage: string | null
  event_type: string
  tool_name: string | null
  decision: string
  reason: string | null
  provenance: ProvenanceEntry[]
  execution_plan_id: string | null
  timestamp: string
  agent_name: string | null
}

export interface TraceDetail {
  trace_id: string
  event_count: number
  execution_plan_ids: string[]
  timeline: TraceEvent[]
  schema_versions_observed: string[]
  provenance_summary: Record<string, number>
  final_decision: string
  final_reason: string | null
}

export interface TraceSummary {
  trace_id: string
  final_decision: string
  final_reason: string | null
  tool_name: string | null
  provenance_trust_summary: Record<string, number>
  event_count: number
  schema_versions_observed: string[]
}

export async function fetchTraces(filters?: TraceFilters): Promise<TraceListItem[]> {
  const params: Record<string, string> = {}
  if (filters?.decision) params.decision = filters.decision
  if (filters?.tool_name) params.tool_name = filters.tool_name
  if (filters?.provenance_trust) params.provenance_trust = filters.provenance_trust

  const res = await client.get('/replay', { params })
  return res.data.traces
}

export async function fetchTrace(traceId: string): Promise<TraceDetail> {
  const res = await client.get(`/replay/${traceId}`)
  return res.data
}

export async function fetchTraceSummary(traceId: string): Promise<TraceSummary> {
  const res = await client.get(`/replay/${traceId}/summary`)
  return res.data
}
