import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'
import { fetchEvents, fetchIocs, fetchDashboardStats, ingestKev, ingestScrape, ingestUrlhaus, extractIocs } from './api'
import type { EventItem, IOC, DashboardStats } from './api'

type View = 'dashboard' | 'iocs' | 'events' | 'ingest' | 'extract'

function ScoreBadge({ score }: { score: number }) {
  const level = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low'
  return <span className={`badge badge-${level}`}>{score}</span>
}

function TypeTag({ type }: { type: string }) {
  return <span className={`type-tag type-${type}`}>{type.toUpperCase()}</span>
}

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className={`stat-card ${accent ? `accent-${accent}` : ''}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export default function App() {
  const [view, setView] = useState<View>('dashboard')
  const [iocs, setIocs] = useState<IOC[]>([])
  const [events, setEvents] = useState<EventItem[]>([])
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [scrapeUrl, setScrapeUrl] = useState('')
  const [extractText, setExtractText] = useState('')
  const [extractResults, setExtractResults] = useState<{ type: string; value: string }[]>([])
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const sources = useMemo(() => Array.from(new Set(iocs.map(i => i.source))).sort(), [iocs])
  const types = useMemo(() => Array.from(new Set(iocs.map(i => i.type))).sort(), [iocs])

  async function loadAll() {
    setLoading(true)
    setError('')
    try {
      const [iocResp, eventResp, statsResp] = await Promise.all([
        fetchIocs({ search, source, type: typeFilter }),
        fetchEvents(),
        fetchDashboardStats(),
      ])
      setIocs(iocResp.results)
      setEvents(eventResp.results)
      setStats(statsResp)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAll() }, []) 

  async function handleIngest(action: () => Promise<unknown>, label: string) {
    setLoading(true); setError(''); setMessage('')
    try {
      const res = await action() as Record<string, unknown>
      const summary = Object.entries(res).map(([k, v]) => `${k}: ${v}`).join(' · ')
      setMessage(`✓ ${label} — ${summary}`)
      await loadAll()
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed: ${label}`)
    } finally {
      setLoading(false)
    }
  }

  async function handleExtract(e: FormEvent) {
    e.preventDefault()
    if (!extractText.trim()) return
    setLoading(true); setError('')
    try {
      const res = await extractIocs(extractText.trim())
      setExtractResults(res.results)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Extraction failed')
    } finally {
      setLoading(false)
    }
  }

  function submitScrape(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!scrapeUrl.trim()) return
    handleIngest(() => ingestScrape(scrapeUrl.trim()), 'Scrape ingest')
  }

  const navItems: { id: View; label: string; icon: string }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: '⬡' },
    { id: 'iocs', label: 'IOCs', icon: '◈' },
    { id: 'events', label: 'Events', icon: '◎' },
    { id: 'ingest', label: 'Ingest', icon: '⊕' },
    { id: 'extract', label: 'Extract', icon: '⊗' },
  ]

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">⬡</div>
          <div>
            <div className="brand-name">CTI</div>
            <div className="brand-sub">Threat Intelligence</div>
          </div>
        </div>
        <nav className="nav">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${view === item.id ? 'active' : ''}`}
              onClick={() => setView(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-dot" />
          <span>API Connected</span>
        </div>
      </aside>

      {/* Main */}
      <main className="main">
        {/* Topbar */}
        <div className="topbar">
          <h1 className="page-title">
            {navItems.find(n => n.id === view)?.label}
          </h1>
          <div className="topbar-actions">
            {loading && <span className="spinner" />}
            <button className="btn-refresh" onClick={loadAll} disabled={loading}>↻ Refresh</button>
          </div>
        </div>

        {message && <div className="alert alert-ok">{message}</div>}
        {error && <div className="alert alert-error">{error}</div>}

        {/* ── DASHBOARD ── */}
        {view === 'dashboard' && stats && (
          <div className="view-dashboard">
            <div className="stats-grid">
              <StatCard label="Total IOCs" value={stats.iocs.total} sub={`+${stats.iocs.last_24h} today`} accent="blue" />
              <StatCard label="High Risk" value={stats.iocs.high_risk} sub="Score ≥ 75" accent="red" />
              <StatCard label="Avg Score" value={stats.iocs.avg_threat_score} accent="yellow" />
              <StatCard label="Events" value={stats.events.total} sub={`+${stats.events.last_24h} today`} accent="green" />
              <StatCard label="Threat Actors" value={stats.threat_actors} />
              <StatCard label="Malware" value={stats.malware} />
            </div>

            <div className="dashboard-grid">
              <div className="panel">
                <h3 className="panel-title">IOCs by Type</h3>
                <div className="bar-chart">
                  {stats.iocs.by_type.map((item: { type: string; count: number }) => (
                    <div key={item.type} className="bar-row">
                      <TypeTag type={item.type} />
                      <div className="bar-track">
                        <div
                          className="bar-fill"
                          style={{ width: `${Math.min(100, (item.count / stats.iocs.total) * 100)}%` }}
                        />
                      </div>
                      <span className="bar-count">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel">
                <h3 className="panel-title">Top Sources</h3>
                <div className="source-list">
                  {stats.iocs.by_source.map((item: { source: string; count: number }, i: number) => (
                    <div key={item.source} className="source-row">
                      <span className="source-rank">#{i + 1}</span>
                      <span className="source-name">{item.source}</span>
                      <span className="source-count">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel panel-wide">
                <h3 className="panel-title">Top Threats</h3>
                <table className="table">
                  <thead>
                    <tr><th>Value</th><th>Type</th><th>Source</th><th>Score</th></tr>
                  </thead>
                  <tbody>
                    {stats.iocs.top_threats.map((t: IOC) => (
                      <tr key={t.id}>
                        <td className="truncate">{t.value}</td>
                        <td><TypeTag type={t.type} /></td>
                        <td>{t.source}</td>
                        <td><ScoreBadge score={t.threat_score} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ── IOCs ── */}
        {view === 'iocs' && (
          <div className="view-content">
            <div className="filters-bar">
              <input
                className="filter-input"
                type="text"
                placeholder="Search value..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && loadAll()}
              />
              <select className="filter-select" value={source} onChange={e => setSource(e.target.value)}>
                <option value="">All sources</option>
                {sources.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
                <option value="">All types</option>
                {types.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <button className="btn-primary" onClick={loadAll} disabled={loading}>Apply</button>
            </div>

            <div className="panel">
              <table className="table">
                <thead>
                  <tr><th>Value</th><th>Type</th><th>Source</th><th>Score</th><th>Tags</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                  {iocs.map(ioc => (
                    <tr key={ioc.id}>
                      <td className="truncate mono">{ioc.value}</td>
                      <td><TypeTag type={ioc.type} /></td>
                      <td>{ioc.source}</td>
                      <td><ScoreBadge score={ioc.threat_score} /></td>
                      <td>
                        {ioc.tags?.map(tag => (
                          <span key={tag} className="tag">{tag}</span>
                        ))}
                      </td>
                      <td className="muted">{new Date(ioc.last_seen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {iocs.length === 0 && !loading && <div className="empty">No IOCs found</div>}
            </div>
          </div>
        )}

        {/* ── EVENTS ── */}
        {view === 'events' && (
          <div className="view-content">
            <div className="panel">
              <table className="table">
                <thead>
                  <tr><th>Source</th><th>Raw Data</th><th>Timestamp</th></tr>
                </thead>
                <tbody>
                  {events.map(ev => (
                    <tr key={ev.id}>
                      <td><span className="source-chip">{ev.source}</span></td>
                      <td className="truncate mono">{ev.raw_data}</td>
                      <td className="muted">{new Date(ev.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {events.length === 0 && !loading && <div className="empty">No events found</div>}
            </div>
          </div>
        )}

        {/* ── INGEST ── */}
        {view === 'ingest' && (
          <div className="view-content">
            <div className="ingest-grid">
              <div className="panel ingest-card">
                <div className="ingest-icon">⬡</div>
                <h3>URLhaus</h3>
                <p>Ingest recent malicious URLs from abuse.ch URLhaus feed.</p>
                <button className="btn-primary" disabled={loading}
                  onClick={() => handleIngest(() => ingestUrlhaus(100), 'URLhaus')}>
                  {loading ? 'Running...' : 'Ingest URLhaus'}
                </button>
              </div>

              <div className="panel ingest-card">
                <div className="ingest-icon">◈</div>
                <h3>CISA KEV</h3>
                <p>Ingest known exploited vulnerabilities from CISA KEV catalog.</p>
                <button className="btn-primary" disabled={loading}
                  onClick={() => handleIngest(() => ingestKev(100), 'CISA KEV')}>
                  {loading ? 'Running...' : 'Ingest CISA KEV'}
                </button>
              </div>

              <div className="panel ingest-card">
                <div className="ingest-icon">◎</div>
                <h3>Scrape URL</h3>
                <p>Extract IOCs from any threat intelligence page.</p>
                <form onSubmit={submitScrape} className="ingest-form">
                  <input
                    className="filter-input"
                    type="url"
                    value={scrapeUrl}
                    placeholder="https://example.com/threat-report"
                    onChange={e => setScrapeUrl(e.target.value)}
                  />
                  <button className="btn-primary" type="submit" disabled={loading || !scrapeUrl.trim()}>
                    {loading ? 'Scraping...' : 'Scrape & Ingest'}
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}

        {/* ── EXTRACT ── */}
        {view === 'extract' && (
          <div className="view-content">
            <div className="panel">
              <h3 className="panel-title">IOC Extractor</h3>
              <p className="muted" style={{ marginBottom: '16px' }}>
                Paste raw text to extract IPs, domains, URLs, hashes, and CVEs.
              </p>
              <form onSubmit={handleExtract} className="extract-form">
                <textarea
                  className="extract-textarea"
                  value={extractText}
                  onChange={e => setExtractText(e.target.value)}
                  placeholder="Paste threat report, log, or any raw text here..."
                  rows={8}
                />
                <button className="btn-primary" type="submit" disabled={loading || !extractText.trim()}>
                  {loading ? 'Extracting...' : 'Extract IOCs'}
                </button>
              </form>
            </div>

            {extractResults.length > 0 && (
              <div className="panel">
                <h3 className="panel-title">Extracted — {extractResults.length} IOCs</h3>
                <table className="table">
                  <thead>
                    <tr><th>#</th><th>Type</th><th>Value</th></tr>
                  </thead>
                  <tbody>
                    {extractResults.map((r, i) => (
                      <tr key={i}>
                        <td className="muted">{i + 1}</td>
                        <td><TypeTag type={r.type} /></td>
                        <td className="mono">{r.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}