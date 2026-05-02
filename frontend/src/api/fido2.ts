function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

export async function registerPasskey(username: string): Promise<void> {
  const optionsRes = await fetch('/api/fido2/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
    credentials: 'include',
  })

  if (!optionsRes.ok) throw new Error(await optionsRes.text())
  const options = await optionsRes.json()

  options.challenge = base64urlToArrayBuffer(options.challenge)
  options.user.id = base64urlToArrayBuffer(options.user.id)
  if (options.excludeCredentials) {
    options.excludeCredentials = options.excludeCredentials.map(
      (c: { id: string; [key: string]: unknown }) => ({ ...c, id: base64urlToArrayBuffer(c.id) })
    )
  }

  const credential = await navigator.credentials.create({ publicKey: options })
  if (!credential) throw new Error('No credential returned from authenticator')

  const credentialJSON = (credential as PublicKeyCredential).toJSON()

  const verifyRes = await fetch('/api/fido2/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, response: credentialJSON }),
    credentials: 'include',
  })

  if (!verifyRes.ok) throw new Error(await verifyRes.text())
  const success = await verifyRes.json()
  if (!success) throw new Error('Server rejected the registration')
}

export async function authenticatePasskey(username: string): Promise<void> {
  const optionsRes = await fetch('/api/fido2/authenticate/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
    credentials: 'include',
  })

  if (!optionsRes.ok) throw new Error(await optionsRes.text())
  const options = await optionsRes.json()

  options.challenge = base64urlToArrayBuffer(options.challenge)
  if (options.allowCredentials) {
    options.allowCredentials = options.allowCredentials.map(
      (c: { id: string; [key: string]: unknown }) => ({ ...c, id: base64urlToArrayBuffer(c.id) })
    )
  }

  const credential = await navigator.credentials.get({ publicKey: options })
  if (!credential) throw new Error('No credential returned from authenticator')

  const credentialJSON = (credential as PublicKeyCredential).toJSON()

  const verifyRes = await fetch('/api/fido2/authenticate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, response: credentialJSON }),
    credentials: 'include',
  })

  if (!verifyRes.ok) throw new Error(await verifyRes.text())
  const success = await verifyRes.json()
  if (!success) throw new Error('Server rejected the authentication')
}
