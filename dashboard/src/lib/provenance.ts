const SOURCE_LABELS: Record<string, string> = {
  user_prompt: 'USER',
  system_prompt: 'SYS',
  skill: 'SKILL',
  retrieval_chunk: 'RAG',
  memory: 'MEM',
  tool_result: 'TOOL',
  agent_message: 'AGENT',
}

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source.slice(0, 6).toUpperCase()
}
