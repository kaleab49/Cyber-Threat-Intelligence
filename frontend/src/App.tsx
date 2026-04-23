import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'
import { fetchEvents, fetchIocs, ingestKev, ingestScrape, ingestUrlhaus } from './api'
import type { EventItem, IOC } from './api'

function App() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [events, setEvents] = useState<EventItem[]>([])
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [scrapeUrl, setScrapeUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const sources = useMemo(() => {
    return Array.from(new Set(iocs.map((ioc) => ioc.source))).sort()
  }, [iocs])

  async function loadData() {
    setLoading(true)
    setError('')
    try {
      const [iocResp, eventResp] = await Promise.all([
        fetchIocs({ search, source }),
        fetchEvents(),
      ])
      setIocs(iocResp.results)
      setEvents(eventResp.results)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleIngest(action: () => Promise<unknown>, successLabel: string) {
    setLoading(true)
    setError('')
    setMessage('')
    try {
      await action()
      setMessage(`${successLabel} completed.`)
      await loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to run ${successLabel}`)
    } finally {
      setLoading(false)
    }
  }

  function submitScrape(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!scrapeUrl.trim()) return
    handleIngest(() => ingestScrape(scrapeUrl.trim()), 'Scrape ingest')
  }

  return (
    <main className="container">
      <header>
        <h1>CyberIntell Collector</h1>
        <p>Ingest and review stored threat data.</p>
      </header>

      <section className="card controls">
        <h2>Ingestion</h2>
        <div className="actions">
          <button disabled={loading} onClick={() => handleIngest(() => ingestUrlhaus(100), 'URLhaus ingest')}>
            Ingest URLhaus
          </button>
          <button disabled={loading} onClick={() => handleIngest(() => ingestKev(100), 'CISA KEV ingest')}>
            Ingest CISA KEV
          </button>
        </div>

        <form onSubmit={submitScrape} className="scrape-form">
          <input
            type="url"
            value={scrapeUrl}
            placeholder="https://example.com/report"
            onChange={(event) => setScrapeUrl(event.target.value)}
          />
          <button type="submit" disabled={loading || !scrapeUrl.trim()}>
            Ingest Scrape URL
          </button>
        </form>

        {message ? <p className="message ok">{message}</p> : null}
        {error ? <p className="message error">{error}</p> : null}
      </section>

      <section className="card">
        <h2>IOC Filters</h2>
        <div className="filters">
          <input
            type="text"
            placeholder="Search IOC value"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <select value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="">All sources</option>
            {sources.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <button disabled={loading} onClick={loadData}>
            Apply
          </button>
        </div>
      </section>

      <section className="card">
        <h2>IOCs ({iocs.length})</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Source</th>
                <th>Score</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id}>
                  <td className="truncate">{ioc.value}</td>
                  <td>{ioc.type}</td>
                  <td>{ioc.source}</td>
                  <td>{ioc.threat_score}</td>
                  <td>{new Date(ioc.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <h2>Events ({events.length})</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Timestamp</th>
                <th>Raw Data</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>{event.source}</td>
                  <td>{new Date(event.timestamp).toLocaleString()}</td>
                  <td className="truncate">{event.raw_data}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

export default App
