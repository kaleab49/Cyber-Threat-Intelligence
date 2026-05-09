import { useState, useEffect, useRef } from 'react'
import './landing.css'
import Login from './Login'

type Props = {
  onLogin: (access: string, refresh: string, username: string) => void
}

function GridBackground() {
  return (
    <div className="grid-bg">
      <div className="grid-lines" />
      <div className="grid-glow" />
      <div className="grid-radial" />
    </div>
  )
}

function AnimatedCounter({ target, suffix = '' }: { target: number; suffix?: string }) {
  const [count, setCount] = useState(0)
  const ref = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          let start = 0
          const step = target / 60
          const timer = setInterval(() => {
            start += step
            if (start >= target) { setCount(target); clearInterval(timer) }
            else setCount(Math.floor(start))
          }, 16)
        }
      },
      { threshold: 0.5 }
    )
    if (ref.current) observer.observe(ref.current)
    return () => observer.disconnect()
  }, [target])

  return <span ref={ref}>{count.toLocaleString()}{suffix}</span>
}

const FEEDS = [
  { name: 'URLhaus', type: 'URL', count: '1.2K', color: '#733efb' },
  { name: 'CISA KEV', type: 'CVE', count: '847', color: '#3784dc' },
  { name: 'ThreatFox', type: 'IOC', count: '3.4K', color: '#00d4ff' },
  { name: 'Threat Feeds', type: 'URL', count: '2.1K', color: '#27e800' },
  { name: 'Darkweb', type: 'IP', count: '512', color: '#ffc233' },
  { name: 'Malwarebazaar', type: 'Malware', count: '512', color: '#ff0000' },
  { name: 'VirusTotal', type: 'Virus , Threat-Actors', count: '3122', color: '#f92e00' },
]

export default function Landing({ onLogin }: Props) {
  const [showLogin, setShowLogin] = useState(false)
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [activeFeed, setActiveFeed] = useState(0)

  useEffect(() => {
    const t = setInterval(() => setActiveFeed(p => (p + 1) % FEEDS.length), 2000)
    return () => clearInterval(t)
  }, [])

  function open(m: 'login' | 'register') {
    setMode(m)
    setShowLogin(true)
  }

  return (
    <div className="landing">
      <GridBackground />

      <nav className="l-nav">
        <div className="l-nav-brand">
          <span className="l-nav-hex">⬡</span>
          <span className="l-nav-name">CTI Platform</span>
        </div>
        <div className="l-nav-links">
          <a href="#features">Features</a>
          <a href="#feeds">Feeds</a>
          <a href="#stats">Stats</a>
        </div>
        <div className="l-nav-actions">
          <button className="l-btn-ghost" onClick={() => open('login')}>Sign in</button>
          <button className="l-btn-primary" onClick={() => open('register')}>Get started</button>
        </div>
      </nav>

      <section className="l-hero">
        <div className="l-badge">
          <span className="l-badge-dot" />
          Live threat intelligence — updated every hour
        </div>

        <h1 className="l-hero-title">
          See every threat.<br />
          <span className="l-hero-accent">Before it sees you.</span>
        </h1>

        <p className="l-hero-desc">
          CTI aggregates, enriches, and visualizes threat intelligence from
          multiple feeds — giving your security team a single, calm place to
          track IOCs, CVEs, and emerging adversary activity.
        </p>

        <div className="l-hero-cta">
          <button className="l-btn-primary l-btn-lg" onClick={() => open('register')}>
            Start for free
            <span className="l-btn-arrow">→</span>
          </button>
          <button className="l-btn-ghost l-btn-lg" onClick={() => open('login')}>
            Sign in to dashboard
          </button>
        </div>

        <div className="l-hero-visual">
          <div className="l-dashboard-mock">
            <div className="l-mock-topbar">
              <div className="l-mock-dots">
                <span /><span /><span />
              </div>
              <div className="l-mock-url">localhost:5173 — CTI Dashboard</div>
            </div>
            <div className="l-mock-body">
              <div className="l-mock-sidebar">
                {['⬡ Dashboard', '◈ IOCs', '◎ Events', '⊕ Ingest', '⊗ Extract'].map((item, i) => (
                  <div key={i} className={`l-mock-nav-item ${i === 0 ? 'active' : ''}`}>{item}</div>
                ))}
              </div>
              <div className="l-mock-content">
                <div className="l-mock-stats">
                  {[
                    { label: 'Total IOCs', val: '4,821', accent: '#4488ff' },
                    { label: 'High Risk', val: '127', accent: '#ff4466' },
                    { label: 'Events', val: '2,340', accent: '#00e89a' },
                    { label: 'Avg Score', val: '42.3', accent: '#ffc233' },
                  ].map(s => (
                    <div key={s.label} className="l-mock-stat" style={{ '--c': s.accent } as React.CSSProperties}>
                      <div className="l-mock-stat-val">{s.val}</div>
                      <div className="l-mock-stat-label">{s.label}</div>
                    </div>
                  ))}
                </div>
                <div className="l-mock-table">
                  {['CVE-2026-31431', '185.220.101.x', 'malware.com', 'CVE-2025-29635', '8.8.8.8'].map((v, i) => (
                    <div key={i} className="l-mock-row">
                      <span className="l-mock-val">{v}</span>
                      <span className={`l-mock-score s${i}`}>{[92, 78, 65, 45, 30][i]}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="l-ticker" id="feeds">
        <div className="l-ticker-track">
          {[...FEEDS, ...FEEDS].map((f, i) => (
            <div key={i} className="l-ticker-item" style={{ '--fc': f.color } as React.CSSProperties}>
              <span className="l-ticker-dot" />
              <span className="l-ticker-name">{f.name}</span>
              <span className="l-ticker-type">{f.type}</span>
              <span className="l-ticker-count">{f.count}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="l-stats" id="stats">
        <div className="l-stats-grid">
          {[
            { value: 200000, suffix: '+', label: 'IOCs processed monthly' },
            { value: 24, suffix: '/7', label: 'Always-on collection' },
            { value: 95, suffix: '%', label: 'IOC classification accuracy' },
            { value: 5, suffix: ' feeds', label: 'Integrated threat sources' },
          ].map((s, i) => (
            <div key={i} className="l-stat-card">
              <div className="l-stat-number">
                <AnimatedCounter target={s.value} suffix={s.suffix} />
              </div>
              <div className="l-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="l-features" id="features">
        <div className="l-section-label">What you get</div>
        <h2 className="l-section-title">Everything a threat analyst needs</h2>

        <div className="l-features-grid">
          {[
            {
              icon: '◈',
              title: 'IOC Tracking',
              desc: 'Track IPs, domains, URLs, hashes and CVEs with automatic normalization, deduplication, and threat scoring.',
              color: '#00d4ff',
            },
            {
              icon: '⊕',
              title: 'Multi-Feed Ingestion',
              desc: 'Pull from URLhaus, CISA KEV, ThreatFox, CERT feeds and darkweb sources — automatically, every hour.',
              color: '#00e89a',
            },
            {
              icon: '◎',
              title: 'Event Timeline',
              desc: 'Every ingestion, enrichment and detection is logged with full context for audit and investigation.',
              color: '#ffc233',
            },
            {
              icon: '⊗',
              title: 'IOC Extraction',
              desc: 'Paste raw threat reports, logs, or emails — extract IPs, domains, hashes and CVEs instantly.',
              color: '#aa88ff',
            },
            {
              icon: '⬡',
              title: 'Relationship Graph',
              desc: 'Visualize connections between IOCs, campaigns, threat actors and malware families.',
              color: '#ff4466',
            },
            {
              icon: '◉',
              title: 'Scheduled Automation',
              desc: 'Celery-powered background tasks run your scrapers on a schedule — no manual effort required.',
              color: '#4488ff',
            },
             
          ].map((f, i) => (
            <div key={i} className="l-feature-card" style={{ '--fc': f.color } as React.CSSProperties}>
              <div className="l-feature-icon">{f.icon}</div>
              <h3 className="l-feature-title">{f.title}</h3>
              <p className="l-feature-desc">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="l-feed-showcase">
        <div className="l-section-label">Threat sources</div>
        <h2 className="l-section-title">Integrated intelligence feeds</h2>
        <div className="l-feed-list">
          {FEEDS.map((f, i) => (
            <div
              key={i}
              className={`l-feed-row ${activeFeed === i ? 'active' : ''}`}
              style={{ '--fc': f.color } as React.CSSProperties}
              onMouseEnter={() => setActiveFeed(i)}
            >
              <div className="l-feed-indicator" />
              <div className="l-feed-info">
                <div className="l-feed-name">{f.name}</div>
                <div className="l-feed-meta">IOC type: {f.type}</div>
              </div>
              <div className="l-feed-count">{f.count} IOCs</div>
              <div className="l-feed-status">● Live</div>
            </div>
          ))}
        </div>
      </section>

      <section className="l-cta">
        <div className="l-cta-glow" />
        <h2 className="l-cta-title">Ready to track threats?</h2>
        <p className="l-cta-desc">Get started in seconds. No credit card required.</p>
        <div className="l-hero-cta">
          <button className="l-btn-primary l-btn-lg" onClick={() => open('register')}>
            Create free account
            <span className="l-btn-arrow">→</span>
          </button>
          <button className="l-btn-ghost l-btn-lg" onClick={() => open('login')}>
            Sign in
          </button>
        </div>
      </section>

      
      <footer className="l-footer">
        <div className="l-footer-brand">
          <span className="l-nav-hex">⬡</span>
          <span>CTI Platform</span>
        </div>
        <div className="l-footer-copy">Built for security teams. Powered by Django + React.</div>
      </footer>

      
      {showLogin && (
        <div className="l-modal-backdrop" onClick={() => setShowLogin(false)}>
          <div className="l-modal-panel" onClick={e => e.stopPropagation()}>
            <button className="l-modal-close" onClick={() => setShowLogin(false)}>✕</button>
            <Login
              onLogin={(access, refresh, username) => {
                onLogin(access, refresh, username)
                setShowLogin(false)
              }}
              initialMode={mode}
            />
          </div>
        </div>
      )}
    </div>
  )
}