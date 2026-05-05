import { useState } from 'react'
import Login from './login'

type Props = {
  onLogin: (access: string, refresh: string, username: string) => void
}

export default function Landing({ onLogin }: Props) {
  const [showLogin, setShowLogin] = useState(false)

  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-brand">
          <div className="landing-logo">CTI</div>
          <div className="landing-brand-text">
            <div className="landing-brand-title">CTI</div>
            <div className="landing-brand-sub">Cyber Threat Intelligence</div>
          </div>
        </div>

        <div className="landing-actions">
          <button className="landing-button secondary" onClick={() => setShowLogin(true)}>
            Login
          </button>
          <button className="landing-button" onClick={() => setShowLogin(true)}>
            Request Access
          </button>
        </div>
      </header>

      <main className="landing-hero">
        <section className="landing-copy">
          <div className="landing-eyebrow"></div>
          <h1 className="landing-title">CTI helps you see the threat picture clearly, without the clutter.</h1>
          <p className="landing-description">
            CTI brings IOC tracking, enriched context, and automated feed ingestion into a friendly,
            easy-to-use hub. Stay one step ahead of adversaries with practical alerts, analyst
            workflows, and a calm operations view built for security teams.
          </p>

          <div className="landing-actions">
            <button className="landing-button" onClick={() => setShowLogin(true)}>
              Start with CTI
            </button>
            <button className="landing-button secondary" onClick={() => setShowLogin(true)}>
              Preview Dashboard
            </button>
          </div>

          <div className="landing-stats">
            <div className="stat-pill">
              <strong>200K+</strong>
              <span>Indicators processed monthly</span>
            </div>
            <div className="stat-pill">
              <strong>24/7</strong>
              <span>Always-on feed collection</span>
            </div>
            <div className="stat-pill">
              <strong>95%</strong>
              <span>Smart IOC classification</span>
            </div>
          </div>
        </section>

        <aside className="landing-hero-visual">
          <div className="visual-panel">
            <h3>Threat feed orchestration</h3>
            <p>Ingest multiple sources automatically, enrich indicators, and surface risk insights in one secure place.</p>
          </div>
          <div className="visual-panel">
            <h3>Investigate fast</h3>
            <p>Search IOCs, uncover campaign links, and prioritize alerts with clear threat scoring.</p>
          </div>
          <div className="visual-panel">
            <h3>Warm analyst experience</h3>
            <p>Move from noisy alerts to a calmer workflow that helps teams focus on what matters.</p>
          </div>
        </aside>
      </main>

      <section className="landing-features">
        <div className="feature-card">
          <h3 className="feature-title">A calm, operator-friendly UI</h3>
          <p className="feature-copy">Quickly browse IOCs, incidents, and feeds with a layout designed for modern SOC teams.</p>
        </div>
        <div className="feature-card">
          <h3 className="feature-title">Complete context in one place</h3>
          <p className="feature-copy">Combine feeds, enrichments, and historic events with timeline-ready visibility.</p>
        </div>
        <div className="feature-card">
          <h3 className="feature-title">Secure ingest & automation</h3>
          <p className="feature-copy">Accept data from external feeds safely, then normalize and enrich it automatically.</p>
        </div>
        <div className="feature-card">
          <h3 className="feature-title">Team-ready collaboration</h3>
          <p className="feature-copy">Share findings, highlight suspicious activity, and keep analysts coordinated without noise.</p>
        </div>
      </section>

      <section className="landing-highlight">
        <p>CTI is built for teams who want intelligence delivered with clarity and comfort. Cozy insights, better decisions, faster response.</p>
      </section>

      {showLogin && (
        <div className="landing-modal-backdrop">
          <div className="landing-modal-panel">
            <Login
              onLogin={(access, refresh, username) => {
                onLogin(access, refresh, username)
                setShowLogin(false)
              }}
              onClose={() => setShowLogin(false)}
            />
          </div>
        </div>
      )}
    </div>
  )
}
