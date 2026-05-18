import type { TraceEvent } from '../api/replayClient'

export interface GraphNode {
  id: string
  nodeType: 'provenance' | 'plan' | 'evaluate' | 'policy' | 'approval' | 'tool' | 'outcome'
  label: string
  sublabel?: string
  decision?: string
  sourceEventId?: string
  provenanceSource?: string
  trustLevel?: string
  x: number
  y: number
}

export interface GraphEdge {
  id: string
  source: string
  target: string
}

export interface ExecutionGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  svgHeight: number
}

function getFirstTrust(events: TraceEvent[], source: string): string {
  for (const ev of events) {
    if (!Array.isArray(ev.provenance)) continue
    for (const p of ev.provenance) {
      if (String(p.source_type ?? p.source ?? '') === source) {
        return String(p.trust_level ?? p.trust ?? '')
      }
    }
  }
  return ''
}

function addEdge(edges: GraphEdge[], source: string, target: string) {
  edges.push({ id: `${source}__${target}`, source, target })
}

export function buildExecutionGraph(events: TraceEvent[]): ExecutionGraph {
  if (!events.length) {
    return {
      nodes: [{ id: 'outcome', nodeType: 'outcome', label: 'NO EVENTS', x: 400, y: 80 }],
      edges: [],
      svgHeight: 200,
    }
  }

  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  let layerY = 80

  // 1. Provenance nodes — one per unique source across all events
  const seenSources = new Set<string>()
  for (const ev of events) {
    if (Array.isArray(ev.provenance)) {
      for (const p of ev.provenance) {
        const src = String(p.source_type ?? p.source ?? '')
        if (src) seenSources.add(src)
      }
    }
  }
  const provNodes: GraphNode[] = []
  const sourceArr = Array.from(seenSources)
  if (sourceArr.length > 0) {
    const spacing = 140
    const startX = 400 - ((sourceArr.length - 1) * spacing) / 2
    sourceArr.forEach((src, i) => {
      const trust = getFirstTrust(events, src)
      const node: GraphNode = {
        id: `prov_${src}`,
        nodeType: 'provenance',
        label: src.toUpperCase().slice(0, 10),
        sublabel: trust || undefined,
        x: startX + i * spacing,
        y: layerY,
        provenanceSource: src,
        trustLevel: trust || undefined,
      }
      nodes.push(node)
      provNodes.push(node)
    })
    layerY += 120
  }

  // 2. Plan node
  const planEvent = events.find(e => e.decision_stage?.toLowerCase() === 'plan')
  let planNode: GraphNode | undefined
  if (planEvent) {
    planNode = { id: 'plan', nodeType: 'plan', label: 'PLAN', sublabel: planEvent.event_type,
      decision: planEvent.decision, sourceEventId: planEvent.event_id ?? undefined, x: 400, y: layerY }
    nodes.push(planNode)
    if (provNodes.length > 0) provNodes.forEach(pn => addEdge(edges, pn.id, 'plan'))
    layerY += 120
  }

  // 3. Evaluate node
  const evalEvent = events.find(e => e.decision_stage?.toLowerCase() === 'evaluate')
  let evalNode: GraphNode | undefined
  if (evalEvent) {
    evalNode = { id: 'evaluate', nodeType: 'evaluate', label: 'EVALUATE', sublabel: evalEvent.event_type,
      decision: evalEvent.decision, sourceEventId: evalEvent.event_id ?? undefined, x: 400, y: layerY }
    nodes.push(evalNode)
    if (planNode) addEdge(edges, 'plan', 'evaluate')
    else if (provNodes.length > 0) provNodes.forEach(pn => addEdge(edges, pn.id, 'evaluate'))
    layerY += 120
  }

  // 4. Approval node (optional)
  const approvalEvent = events.find(e =>
    e.decision_stage?.toLowerCase() === 'approval' || e.decision === 'require_approval'
  )
  let approvalNode: GraphNode | undefined
  if (approvalEvent) {
    approvalNode = { id: 'approval', nodeType: 'approval', label: 'APPROVAL', sublabel: 'requires review',
      decision: approvalEvent.decision, sourceEventId: approvalEvent.event_id ?? undefined, x: 400, y: layerY }
    nodes.push(approvalNode)
    const prev = evalNode?.id ?? planNode?.id
    if (prev) addEdge(edges, prev, 'approval')
    layerY += 120
  }

  // 5. Tool node (execute stage)
  const toolEvent = events.find(e => e.decision_stage?.toLowerCase() === 'execute')
  let toolNode: GraphNode | undefined
  if (toolEvent) {
    toolNode = { id: 'tool', nodeType: 'tool', label: (toolEvent.tool_name ?? 'TOOL').toUpperCase(),
      sublabel: toolEvent.event_type, decision: toolEvent.decision,
      sourceEventId: toolEvent.event_id ?? undefined, x: 400, y: layerY }
    nodes.push(toolNode)
    const prev = approvalNode?.id ?? evalNode?.id ?? planNode?.id
    if (prev) addEdge(edges, prev, 'tool')
    layerY += 120
  }

  // 6. Outcome node (synthetic terminal)
  const last = events[events.length - 1]
  const reason = last.reason ?? ''
  const outcomeNode: GraphNode = {
    id: 'outcome', nodeType: 'outcome', label: last.decision.toUpperCase(),
    sublabel: reason.length > 40 ? reason.slice(0, 40) + '…' : reason,
    decision: last.decision, x: 400, y: layerY,
  }
  nodes.push(outcomeNode)
  const prevId = toolNode?.id ?? approvalNode?.id ?? evalNode?.id ?? planNode?.id
  if (prevId) addEdge(edges, prevId, 'outcome')
  else provNodes.forEach(pn => addEdge(edges, pn.id, 'outcome'))

  return { nodes, edges, svgHeight: layerY + 80 }
}
