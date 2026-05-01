import { useState } from 'react'
import { registerPasskey } from './api/fido2'
import styles from './App.module.css'

type Status = { type: 'idle' | 'loading' | 'success' | 'error'; message?: string }

export default function App() {
  const [username, setUsername] = useState('')
  const [status, setStatus] = useState<Status>({ type: 'idle' })

  function friendlyError(e: unknown): string {
    const msg = e instanceof Error ? e.message : ''
    if (msg.includes('404') || msg.includes('Not Found')) return 'Could not reach the server. Make sure the backend is running.'
    if (msg.includes('NetworkError') || msg.includes('Failed to fetch')) return 'No connection to the server. Check that the backend is running.'
    if (msg.includes('NotAllowedError')) return 'Authentication was cancelled or timed out. Please try again.'
    if (msg.includes('rejected')) return 'Registration was rejected by the server. Please try again.'
    if (msg.trim()) return msg
    return 'Something went wrong. Please try again.'
  }

  async function handleRegister() {
    if (!username.trim()) {
      setStatus({ type: 'error', message: 'Please enter a username.' })
      return
    }
    setStatus({ type: 'loading' })
    try {
      await registerPasskey(username.trim())
      setStatus({ type: 'success', message: 'Your passkey was registered successfully.' })
    } catch (e) {
      setStatus({ type: 'error', message: friendlyError(e) })
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.header}>
          <h1 className={styles.title}>Register a Passkey</h1>
          <p className={styles.subtitle}>
            Use your device biometrics or security key to create a passkey.
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
            onKeyDown={e => e.key === 'Enter' && handleRegister()}
            disabled={status.type === 'loading'}
          />
          <button
            className={styles.button}
            onClick={handleRegister}
            disabled={status.type === 'loading'}
          >
            {status.type === 'loading' ? 'Waiting for authenticator…' : 'Continue'}
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
