import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { TraceList } from './pages/TraceList'
import { TraceDetail } from './pages/TraceDetail'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
})

function Nav() {
  return (
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900 shrink-0">
      <span className="font-mono font-semibold text-sm text-slate-100 tracking-tight">
        AISecOps Interceptor
      </span>
      <span className="font-mono text-xs text-slate-500 tracking-wide uppercase">
        Replay Audit
      </span>
    </header>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="flex flex-col h-full bg-slate-950 text-slate-100">
          <Nav />
          <main className="flex-1 overflow-hidden flex flex-col">
            <Routes>
              <Route path="/" element={<TraceList />} />
              <Route path="/trace/:traceId" element={<TraceDetail />} />
            </Routes>
          </main>
        </div>
      </Router>
    </QueryClientProvider>
  )
}
