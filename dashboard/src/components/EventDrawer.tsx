import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { TraceEvent } from '../api/replayClient'
import { copyToClipboard } from '../lib/clipboard'
import { ProvenanceBadge } from './ProvenanceBadge'

interface EventDrawerProps {
  event: TraceEvent | null
  onClose: () => void
}

export function EventDrawer({ event, onClose }: EventDrawerProps) {
  useEffect(() => {
    if (!event) return
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [event, onClose])

  if (!event) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer panel */}
      <div className="fixed right-0 top-0 h-full w-full max-w-2xl z-50 flex flex-col bg-slate-900 border-l border-slate-800 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <div>
            <p className="text-xs text-slate-400 uppercase tracking-wide">Event Detail</p>
            <p className="font-mono text-sm text-slate-200 mt-0.5 truncate">
              {event.event_id ?? 'no-id'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {event.event_id && (
              <button
                onClick={() => copyToClipboard(event.event_id!)}
                className="text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded-sm"
              >
                Copy ID
              </button>
            )}
            <button
              onClick={() => copyToClipboard(JSON.stringify(event, null, 2))}
              className="text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded-sm transition-colors"
            >
              Copy JSON
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              aria-label="Close drawer"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Provenance section */}
        {Array.isArray(event.provenance) && event.provenance.length > 0 && (
          <div className="px-4 py-3 border-b border-slate-800">
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Provenance</p>
            <ProvenanceBadge entries={event.provenance} maxVisible={8} />
          </div>
        )}

        {/* JSON body */}
        <div className="flex-1 overflow-auto p-4">
          <pre className="bg-slate-950 text-green-400 font-mono text-xs leading-relaxed p-4 rounded overflow-auto whitespace-pre-wrap break-words border border-slate-800">
            {JSON.stringify(event, null, 2)}
          </pre>
        </div>
      </div>
    </>
  )
}
