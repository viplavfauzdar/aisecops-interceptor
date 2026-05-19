import type { PlanMetadata, PlanStep } from '../api/replayClient'
import { RiskBadge } from './RiskBadge'

interface PlanPanelProps {
  plan?: PlanMetadata | null
}

function hasPlan(plan?: PlanMetadata | null): boolean {
  return Boolean(
    plan?.plan_id ||
    plan?.intent ||
    plan?.plan_intent ||
    plan?.risk_level ||
    plan?.plan_risk_level ||
    plan?.requested_capabilities?.length ||
    plan?.plan_steps?.length ||
    plan?.user_input ||
    plan?.model_output,
  )
}

function compact(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value))))
}

function requestedTool(plan: PlanMetadata): string | null {
  return plan.requested_tool ?? plan.plan_steps?.find(step => step.tool_name)?.tool_name ?? null
}

function targets(plan: PlanMetadata): string[] {
  return plan.targets?.length
    ? plan.targets
    : compact(plan.plan_steps?.map(step => step.target) ?? [])
}

function stepCount(plan: PlanMetadata): number {
  return plan.step_count ?? plan.plan_steps?.length ?? 0
}

function capabilityPills(capabilities?: string[] | null) {
  if (!capabilities?.length) return <span className="text-slate-500">none</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {capabilities.map(capability => (
        <span
          key={capability}
          className="px-2 py-0.5 rounded border border-cyan-900 bg-cyan-950/50 text-cyan-300 text-[11px] font-mono"
        >
          {capability}
        </span>
      ))}
    </div>
  )
}

function renderTextBlock(label: string, value?: string | null) {
  if (!value) return null
  return (
    <div>
      <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
      <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-300 whitespace-pre-wrap break-words max-h-40 overflow-auto">
        {value}
      </pre>
    </div>
  )
}

function stepValue(value?: string | null) {
  return value || <span className="text-slate-600">-</span>
}

function PlanStepsTable({ steps }: { steps: PlanStep[] }) {
  if (!steps.length) return null

  return (
    <div>
      <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Plan Steps</p>
      <div className="overflow-x-auto border border-slate-800 rounded">
        <table className="min-w-full text-xs">
          <thead className="bg-slate-950 text-slate-500">
            <tr>
              <th className="px-2 py-2 text-left font-medium">Order</th>
              <th className="px-2 py-2 text-left font-medium">Intent</th>
              <th className="px-2 py-2 text-left font-medium">Tool</th>
              <th className="px-2 py-2 text-left font-medium">Capability</th>
              <th className="px-2 py-2 text-left font-medium">Target</th>
              <th className="px-2 py-2 text-left font-medium">Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {steps
              .slice()
              .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
              .map((step, index) => (
                <tr key={step.step_id ?? index} className="text-slate-300">
                  <td className="px-2 py-2 font-mono">{step.order ?? index + 1}</td>
                  <td className="px-2 py-2">{stepValue(step.intent)}</td>
                  <td className="px-2 py-2 font-mono">{stepValue(step.tool_name)}</td>
                  <td className="px-2 py-2 font-mono">{stepValue(step.capability)}</td>
                  <td className="px-2 py-2 font-mono">{stepValue(step.target)}</td>
                  <td className="px-2 py-2">
                    <RiskBadge riskLevel={step.risk_level} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export function PlanPanel({ plan }: PlanPanelProps) {
  if (!hasPlan(plan)) {
    return (
      <section className="border border-slate-800 rounded bg-slate-900/60 p-4">
        <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Plan</p>
        <p className="text-sm text-slate-400">
          No structured plan metadata was recorded for this trace.
        </p>
      </section>
    )
  }

  const planData = plan!
  const intent = planData.intent ?? planData.plan_intent ?? 'unknown'
  const riskLevel = planData.risk_level ?? planData.plan_risk_level
  const tool = requestedTool(planData)
  const targetList = targets(planData)
  const steps = planData.plan_steps ?? []

  return (
    <section className="border border-slate-800 rounded bg-slate-900/60 p-4 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider">Plan</p>
          <p className="font-mono text-sm text-slate-200 mt-1 truncate">
            {planData.plan_id ?? 'no-plan-id'}
          </p>
        </div>
        <RiskBadge riskLevel={riskLevel} size="md" />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Intent</p>
          <p className="text-sm text-slate-200 font-mono break-words">{intent}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Requested Tool</p>
          <p className="text-sm text-slate-200 font-mono break-words">{tool ?? 'unknown'}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Targets</p>
          <p className="text-sm text-slate-300 font-mono break-words">
            {targetList.length ? targetList.join(', ') : 'none'}
          </p>
        </div>
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Step Count</p>
          <p className="text-sm text-slate-200 font-mono">{stepCount(planData)}</p>
        </div>
      </div>

      <div>
        <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Requested Capabilities</p>
        {capabilityPills(planData.requested_capabilities)}
      </div>

      <PlanStepsTable steps={steps} />

      {renderTextBlock('User Input', planData.user_input)}
      {renderTextBlock('Model Output', planData.model_output)}
    </section>
  )
}
