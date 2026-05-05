import { useState, type FormEvent } from 'react';

type Props = {
  onLogin: (access: string, refresh: string, username: string) => void;
  initialMode?: 'login' | 'register';
};

export default function Login({ onLogin, initialMode = 'login' }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState<'login' | 'register'>(initialMode);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password');
      return;
    }

    setLoading(true);
    setError('');

    const endpoint = mode === 'login' 
      ? '/api/auth/login/' 
      : '/api/auth/register/';

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          username: username.trim(), 
          password: password.trim() 
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || data.detail || 'Authentication failed');
      }

      onLogin(data.access, data.refresh, data.username || username);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-card">
      <div className="login-brand">
        <div className="login-icon">⬡</div>
        <div className="login-title">CTI Platform</div>
        <div className="login-sub">Cyber Threat Intelligence</div>
      </div>

      <div className="login-tabs">
        <button 
          className={`login-tab ${mode === 'login' ? 'active' : ''}`}
          onClick={() => setMode('login')}
          type="button"
        >
          Login
        </button>
        <button 
          className={`login-tab ${mode === 'register' ? 'active' : ''}`}
          onClick={() => setMode('register')}
          type="button"
        >
          Register
        </button>
      </div>

      <form onSubmit={handleSubmit} className="login-form">
        <div className="login-field">
          <label>Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            autoFocus
            disabled={loading}
          />
        </div>

        <div className="login-field">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            disabled={loading}
          />
        </div>

        {error && <div className="login-error">{error}</div>}

        <button className="login-btn" type="submit" disabled={loading}>
          {loading 
            ? 'Please wait...' 
            : mode === 'login' 
              ? 'Login' 
              : 'Create Account'
          }
        </button>
      </form>
    </div>
  );
}