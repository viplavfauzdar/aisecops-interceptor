import type { TraceEvent } from '../api/replayClient'
import { buildExecutionGraph, type GraphNode } from '../lib/buildExecutionGraph'

interface Props {
  events: TraceEvent[]
  onNodeClick: (eventId: string) => void
}

type RGB = { fill: string; stroke: string; text: string }

const COLORS: Record<string, RGB> = {
  provenance: { fill: '#2e1065', stroke: '#7c3aed', text: '#c4b5fd' },
  plan:       { fill: '#1e3a8a', stroke: '#2563eb', text: '#93c5fd' },
  evaluate:   { fill: '#78350f', stroke: '#d97706', text: '#fcd34d' },
  policy:     { fill: '#78350f', stroke: '#d97706', text: '#fcd34d' },
  approval:   { fill: '#431407', stroke: '#ea580c', text: '#fdba74' },
  tool:       { fill: '#052e16', stroke: '#16a34a', text: '#86efac' },
  outcome:    { fill: '#1e293b', stroke: '#475569', text: '#cbd5e1' },
}

const OUTCOME_COLORS: Record<string, RGB> = {
  allow:            { fill: '#052e16', stroke: '#16a34a', text: '#86efac' },
  allowed:          { fill: '#052e16', stroke: '#16a34a', text: '#86efac' },
  block:            { fill: '#450a0a', stroke: '#dc2626', text: '#fca5a5' },
  blocked:          { fill: '#450a0a', stroke: '#dc2626', text: '#fca5a5' },
  require_approval: { fill: '#431407', stroke: '#ea580c', text: '#fdba74' },
  pending:          { fill: '#0f172a', stroke: '#475569', text: '#94a3b8' },
  dry_run:          { fill: '#2e1065', stroke: '#7c3aed', text: '#c4b5fd' },
}

function colorFor(node: GraphNode): RGB {
  if (node.nodeType === 'outcome') {
    return OUTCOME_COLORS[node.decision?.toLowerCase() ?? ''] ?? COLORS.outcome
  }
  return COLORS[node.nodeType] ?? COLORS.outcome
}

const NODE_W = 140
const NODE_H = 44
const HW = NODE_W / 2
const HH = NODE_H / 2

function NodeRect({ node, onClick }: { node: GraphNode; onClick: () => void }) {
  const c = colorFor(node)
  const clickable = !!node.sourceEventId
  return (
    <g
      transform={`translate(${node.x},${node.y})`}
      onClick={clickable ? onClick : undefined}
      style={{ cursor: clickable ? 'pointer' : 'default' }}
    >
      <rect x={-HW} y={-HH} width={NODE_W} height={NODE_H} rx={2}
        fill={c.fill} stroke={c.stroke} strokeWidth={1} />
      <text x={0} y={node.sublabel ? -5 : 6} textAnchor="middle"
        fill={c.text} fontSize={11} fontFamily="monospace" fontWeight="600">
        {node.label}
      </text>
      {node.sublabel && (
        <text x={0} y={12} textAnchor="middle"
          fill={c.text} fontSize={9} fontFamily="monospace" opacity={0.65}>
          {node.sublabel}
        </text>
      )}
    </g>
  )
}

export function ExecutionGraph({ events, onNodeClick }: Props) {
  const graph = buildExecutionGraph(events)
  const nodeMap = new Map(graph.nodes.map(n => [n.id, n]))

  return (
    <div className="w-full overflow-x-auto bg-slate-950 rounded-sm border border-slate-800">
      <svg
        width="800"
        height={graph.svgHeight}
        viewBox={`0 0 800 ${graph.svgHeight}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ display: 'block', minWidth: '100%' }}
      >
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="6"
            refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="#475569" />
          </marker>
          {/* Subtle dot grid background */}
          <pattern id="dots" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="#334155" />
          </pattern>
        </defs>

        <rect width="800" height={graph.svgHeight} fill="url(#dots)" />

        {/* Edges */}
        {graph.edges.map(edge => {
          const src = nodeMap.get(edge.source)
          const tgt = nodeMap.get(edge.target)
          if (!src || !tgt) return null
          const x1 = src.x, y1 = src.y + HH
          const x2 = tgt.x, y2 = tgt.y - HH - 6  // leave room for arrowhead
          return (
            <line key={edge.id}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="#475569" strokeWidth={1.5}
              markerEnd="url(#arrow)" />
          )
        })}

        {/* Nodes */}
        {graph.nodes.map(node => (
          <NodeRect
            key={node.id}
            node={node}
            onClick={() => node.sourceEventId && onNodeClick(node.sourceEventId)}
          />
        ))}
      </svg>
    </div>
  )
}
