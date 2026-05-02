import { useState } from 'react'
import { registerPasskey, authenticatePasskey } from './api/fido2'
import styles from './App.module.css'

type Status = { type: 'idle' | 'loading' | 'success' | 'error'; message?: string }
type View = 'register' | 'authenticate'

export default function App() {
  const [view, setView] = useState<View>('register')
  const [username, setUsername] = useState('')
  const [status, setStatus] = useState<Status>({ type: 'idle' })

  function friendlyError(e: unknown): string {
    const msg = e instanceof Error ? e.message : ''
    if (msg.includes('404') || msg.includes('Not Found')) return 'Could not reach the server. Make sure the backend is running.'
    if (msg.includes('NetworkError') || msg.includes('Failed to fetch')) return 'No connection to the server. Check that the backend is running.'
    if (msg.includes('NotAllowedError')) return 'Authentication was cancelled or timed out. Please try again.'
    if (msg.includes('rejected')) return `${view === 'register' ? 'Registration' : 'Authentication'} was rejected by the server. Please try again.`
    if (msg.trim()) return msg
    return 'Something went wrong. Please try again.'
  }

  function switchView(next: View) {
    setView(next)
    setStatus({ type: 'idle' })
  }

  async function handleSubmit() {
    if (!username.trim()) {
      setStatus({ type: 'error', message: 'Please enter a username.' })
      return
    }
    setStatus({ type: 'loading' })
    try {
      if (view === 'register') {
        await registerPasskey(username.trim())
        setStatus({ type: 'success', message: 'Your passkey was registered successfully.' })
      } else {
        await authenticatePasskey(username.trim())
        setStatus({ type: 'success', message: 'Authentication successful.' })
      }
    } catch (e) {
      setStatus({ type: 'error', message: friendlyError(e) })
    }
  }

  const isRegister = view === 'register'

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${isRegister ? styles.tabActive : ''}`}
            onClick={() => switchView('register')}
          >
            Register
          </button>
          <button
            className={`${styles.tab} ${!isRegister ? styles.tabActive : ''}`}
            onClick={() => switchView('authenticate')}
          >
            Sign in
          </button>
        </div>

        <div className={styles.header}>
          <h1 className={styles.title}>
            {isRegister ? 'Register a Passkey' : 'Sign in with a Passkey'}
          </h1>
          <p className={styles.subtitle}>
            {isRegister
              ? 'Use your device biometrics or security key to create a passkey.'
              : 'Use your saved passkey to sign in to your account.'}
          </p>
        </div>

        <div className={styles.form}>
          <label className={styles.label} htmlFor="username">Username</label>
          <input
            id="username"
            className={styles.input}
            type="text"
            placeholder="e.g. john_doe"
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            disabled={status.type === 'loading'}
          />
          <button
            className={styles.button}
            onClick={handleSubmit}
            disabled={status.type === 'loading'}
          >
            {status.type === 'loading'
              ? 'Waiting for authenticator…'
              : isRegister ? 'Register' : 'Sign in'}
          </button>
        </div>

        {status.type !== 'idle' && (
          <div className={`${styles.status} ${styles[status.type]}`}>
            {status.message}
          </div>
        )}
      </div>
    </div>
  )
}
