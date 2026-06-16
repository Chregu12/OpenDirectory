import { generateCodeVerifier, generateCodeChallenge } from './pkce';

const AUTH_URL = process.env.NEXT_PUBLIC_OIDC_ISSUER || 'http://localhost:3001';
const CLIENT_ID = 'web-app';
const REDIRECT_URI = typeof window !== 'undefined'
  ? `${window.location.origin}/auth/callback`
  : 'http://localhost:3000/auth/callback';

export async function startLogin() {
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  sessionStorage.setItem('pkce_verifier', verifier);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email roles offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: crypto.randomUUID(),
  });

  window.location.href = `${AUTH_URL}/authorize?${params}`;
}

export async function handleCallback(code: string): Promise<TokenSet> {
  const verifier = sessionStorage.getItem('pkce_verifier');
  sessionStorage.removeItem('pkce_verifier');

  const response = await fetch(`${AUTH_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: verifier!,
    }),
  });

  if (!response.ok) throw new Error('Token exchange failed');
  return response.json();
}

export async function refreshTokens(refreshToken: string): Promise<TokenSet> {
  const response = await fetch(`${AUTH_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });
  if (!response.ok) throw new Error('Refresh failed');
  return response.json();
}

export function logout(idToken?: string) {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    post_logout_redirect_uri: window.location.origin,
  });
  if (idToken) params.set('id_token_hint', idToken);
  window.location.href = `${AUTH_URL}/end_session?${params}`;
}

export function getAccessToken(): string | null {
  return localStorage.getItem('access_token');
}

export function setTokens(tokens: TokenSet) {
  localStorage.setItem('access_token', tokens.access_token);
  if (tokens.refresh_token) localStorage.setItem('refresh_token', tokens.refresh_token);
}

export interface TokenSet {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}
