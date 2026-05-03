export type PaginatedResponse<T> = {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export type IOC = {
  id: string
  value: string
  type: string
  source: string
  threat_score: number
  first_seen: string
  last_seen: string
  tags: string[] | null
}

export type EventItem = {
  id: string
  source: string
  raw_data: string
  parsed_data: Record<string, unknown> | null
  timestamp: string
  created_at: string
}

export type DashboardStats = {
  generated_at: string
  iocs: {
    total: number
    last_24h: number
    last_7d: number
    high_risk: number
    avg_threat_score: number
    max_threat_score: number
    by_type: { type: string; count: number }[]
    by_source: { source: string; count: number }[]
    daily_trend: { day: string; count: number }[]
    top_threats: IOC[]
  }
  events: {
    total: number
    last_24h: number
    last_7d: number
    by_source: { source: string; count: number }[]
  }
  threat_actors: number
  malware: number
  campaigns: number
}

export type ExtractResult = {
  count: number
  results: { type: string; value: string }[]
}

type IngestResult = Record<string, unknown>

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
    ...init,
  })
  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(errorText || `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export async function fetchIocs(params?: {
  search?: string
  source?: string
  type?: string
}): Promise<PaginatedResponse<IOC>> {
  const sp = new URLSearchParams()
  if (params?.search) sp.set('search', params.search)
  if (params?.source) sp.set('source', params.source)
  if (params?.type) sp.set('type', params.type)
  const q = sp.toString()
  return request<PaginatedResponse<IOC>>(q ? `/iocs/?${q}` : '/iocs/')
}

export async function fetchEvents(): Promise<PaginatedResponse<EventItem>> {
  return request<PaginatedResponse<EventItem>>('/events/')
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>('/analytics/dashboard/')
}

export async function extractIocs(text: string): Promise<ExtractResult> {
  return request<ExtractResult>('/ioc/extract/', {
    method: 'POST',
    body: JSON.stringify({ text }),
  })
}

export async function ingestUrlhaus(limit = 100): Promise<IngestResult> {
  return request<IngestResult>('/feeds/ingest/urlhaus/recent/', {
    method: 'POST',
    body: JSON.stringify({ limit }),
  })
}

export async function ingestKev(limit = 100): Promise<IngestResult> {
  return request<IngestResult>('/feeds/ingest/cisa/kev/', {
    method: 'POST',
    body: JSON.stringify({ limit }),
  })
}

export async function ingestScrape(url: string, limit = 500): Promise<IngestResult> {
  return request<IngestResult>('/feeds/ingest/scrape/', {
    method: 'POST',
    body: JSON.stringify({ url, source: 'web-scrape', limit }),
  })
}

export async function runAllScrapers(): Promise<IngestResult> {
  return request<IngestResult>('/scrapers/run-all/', { method: 'POST' })
}

export async function runScraper(name: string): Promise<IngestResult> {
  return request<IngestResult>(`/scrapers/${name}/`, { method: 'POST' })
}