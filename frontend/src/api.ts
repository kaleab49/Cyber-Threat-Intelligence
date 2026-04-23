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
}): Promise<PaginatedResponse<IOC>> {
  const searchParams = new URLSearchParams()
  if (params?.search) searchParams.set('search', params.search)
  if (params?.source) searchParams.set('source', params.source)
  const query = searchParams.toString()
  return request<PaginatedResponse<IOC>>(`/iocs/${query ? `?${query}` : ''}`)
}

export async function fetchEvents(): Promise<PaginatedResponse<EventItem>> {
  return request<PaginatedResponse<EventItem>>('/events/')
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
