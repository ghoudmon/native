import * as WebBrowser from 'expo-web-browser';
import { secureFetch } from './client-cert';
import { resolveSrv, pickSrvTarget, DnsUnsupportedError } from './dns';
import { sha256Bytes } from './sha256';

// Native OAuth machinery. Two entry points share the same PKCE tail:
//
//   • runDiscoveryLogin(email) — given just an email, resolves the JMAP host
//     via `_jmap._tcp.<domain>` SRV, probes the host's .well-known endpoints
//     for OAuth metadata, attempts RFC 7591 dynamic client registration, and
//     finishes with a browser-based PKCE flow.
//   • runOAuthLogin({ issuerUrl, clientId, ... }) — when the user supplies
//     OAuth parameters manually. Skips SRV + registration but still probes
//     .well-known on the issuer and runs the same PKCE tail.
//
// A separate refresh helper exists for the long-lived case where the JMAP
// client needs to mint a fresh access token from a stored refresh token.

export const HANDOFF_REDIRECT_URI = 'bulwarkmobile://auth/callback';
export const DEFAULT_CLIENT_ID = 'bulwark-android';

const DEFAULT_SCOPES = ['openid', 'offline_access'];

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number; // epoch ms
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
}

export interface OAuthMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  scopesSupported?: string[];
}

export interface OAuthLoginResult {
  tokens: OAuthTokens;
  jmapServerUrl: string;
}

export interface OAuthManualConfig {
  jmapServerUrl: string;
  issuerUrl: string;
  clientId?: string;
  clientSecret?: string;
}

export class OAuthError extends Error {}
export class OAuthCancelledError extends OAuthError {
  constructor() {
    super('Sign-in cancelled');
  }
}
export class DiscoveryError extends Error {}

// ── refresh ────────────────────────────────────────────────────

export async function refreshOAuthAccessToken(tokens: OAuthTokens): Promise<OAuthTokens> {
  if (!tokens.refreshToken) {
    throw new OAuthError('No refresh token available');
  }
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: tokens.refreshToken,
    client_id: tokens.clientId,
  });
  if (tokens.clientSecret) body.set('client_secret', tokens.clientSecret);
  const response = await secureFetch(tokens.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new OAuthError(`Token refresh failed: ${response.status}`);
  }
  const data = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
  if (!data.access_token) {
    throw new OAuthError('Token refresh response missing access_token');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? tokens.refreshToken,
    expiresAt: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    tokenEndpoint: tokens.tokenEndpoint,
    clientId: tokens.clientId,
    clientSecret: tokens.clientSecret,
  };
}

// ── public entry points ─────────────────────────────────────────

export async function runOAuthLogin(cfg: OAuthManualConfig): Promise<OAuthLoginResult> {
  const issuer = trimTrailingSlash(cfg.issuerUrl);
  const metadata = await fetchOAuthMetadata(issuer);
  const tokens = await runPkceFlow(metadata, {
    clientId: cfg.clientId?.trim() || DEFAULT_CLIENT_ID,
    clientSecret: cfg.clientSecret?.trim() || undefined,
  });
  return { tokens, jmapServerUrl: trimTrailingSlash(cfg.jmapServerUrl) };
}

export async function runDiscoveryLogin(email: string): Promise<OAuthLoginResult> {
  const domain = extractEmailDomain(email);
  if (!domain) throw new DiscoveryError('Could not parse email domain');

  const jmapServerUrl = await discoverJmapServerUrl(domain);
  const metadata = await fetchOAuthMetadata(jmapServerUrl);

  // RFC 7591 dynamic registration — best-effort. If it succeeds we use the
  // server-assigned client_id (which may differ from what we asked for);
  // otherwise we fall back to the static identifier baked into the manifest
  // entry on the IdP side.
  let clientId = DEFAULT_CLIENT_ID;
  let clientSecret: string | undefined;
  if (metadata.registrationEndpoint) {
    try {
      const registered = await registerClient(metadata.registrationEndpoint);
      clientId = registered.clientId;
      clientSecret = registered.clientSecret;
    } catch {
      // Registration failed (server rejects open registration, network hiccup,
      // etc.) — proceed with the static client_id. If the IdP doesn't know
      // about it the auth call will surface a clear error to the user.
    }
  }

  const tokens = await runPkceFlow(metadata, { clientId, clientSecret });
  return { tokens, jmapServerUrl };
}

// ── discovery primitives ────────────────────────────────────────

function extractEmailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(at + 1).trim().toLowerCase();
}

async function discoverJmapServerUrl(domain: string): Promise<string> {
  let records;
  try {
    records = await resolveSrv(`_jmap._tcp.${domain}`);
  } catch (err) {
    if (err instanceof DnsUnsupportedError) {
      throw new DiscoveryError(
        'DNS auto-discovery is not supported on this device — use advanced settings',
      );
    }
    throw new DiscoveryError(
      err instanceof Error ? err.message : 'DNS lookup failed',
    );
  }
  const pick = pickSrvTarget(records);
  if (!pick) throw new DiscoveryError(`No JMAP service published for ${domain}`);
  const host = pick.target.replace(/\.$/, '');
  const port = pick.port === 443 ? '' : `:${pick.port}`;
  return `https://${host}${port}`;
}

async function fetchOAuthMetadata(serverUrl: string): Promise<OAuthMetadata> {
  const base = trimTrailingSlash(serverUrl);
  const candidates = [
    `${base}/.well-known/openid-configuration`,
    `${base}/.well-known/oauth-authorization-server`,
  ];
  let lastError: unknown;
  for (const url of candidates) {
    try {
      const response = await secureFetch(url, {
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        lastError = new DiscoveryError(`${url} returned ${response.status}`);
        continue;
      }
      const data = (await response.json()) as Record<string, unknown>;
      const authorization = typeof data.authorization_endpoint === 'string'
        ? data.authorization_endpoint
        : null;
      const token = typeof data.token_endpoint === 'string' ? data.token_endpoint : null;
      if (!authorization || !token) {
        lastError = new DiscoveryError(`${url} missing required endpoints`);
        continue;
      }
      const scopes = Array.isArray(data.scopes_supported)
        ? (data.scopes_supported.filter((s) => typeof s === 'string') as string[])
        : undefined;
      return {
        issuer: typeof data.issuer === 'string' ? data.issuer : base,
        authorizationEndpoint: authorization,
        tokenEndpoint: token,
        registrationEndpoint:
          typeof data.registration_endpoint === 'string'
            ? data.registration_endpoint
            : undefined,
        scopesSupported: scopes,
      };
    } catch (err) {
      lastError = err;
    }
  }
  throw new DiscoveryError(
    lastError instanceof Error
      ? `OAuth discovery failed: ${lastError.message}`
      : 'OAuth discovery failed',
  );
}

async function registerClient(
  registrationEndpoint: string,
): Promise<{ clientId: string; clientSecret?: string }> {
  const body = {
    client_name: 'Bulwark Mobile',
    client_id: DEFAULT_CLIENT_ID,
    redirect_uris: [HANDOFF_REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    application_type: 'native',
  };
  const response = await secureFetch(registrationEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new OAuthError(`Dynamic registration failed: ${response.status}`);
  }
  const data = (await response.json()) as {
    client_id?: string;
    client_secret?: string;
  };
  if (!data.client_id) {
    throw new OAuthError('Registration response missing client_id');
  }
  return { clientId: data.client_id, clientSecret: data.client_secret };
}

// ── PKCE flow ───────────────────────────────────────────────────

interface PkceClient {
  clientId: string;
  clientSecret?: string;
}

async function runPkceFlow(
  metadata: OAuthMetadata,
  client: PkceClient,
): Promise<OAuthTokens> {
  const verifier = randomCodeVerifier();
  const challenge = base64UrlEncode(sha256Bytes(asciiBytes(verifier)));
  const state = randomState();
  const scopes = mergeScopes(metadata.scopesSupported);

  const authUrl = buildAuthorizationUrl(metadata.authorizationEndpoint, {
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: HANDOFF_REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    scope: scopes.join(' '),
  });

  const result = await WebBrowser.openAuthSessionAsync(authUrl, HANDOFF_REDIRECT_URI);
  if (result.type === 'cancel' || result.type === 'dismiss') {
    throw new OAuthCancelledError();
  }
  if (result.type !== 'success' || !result.url) {
    throw new OAuthError(`Sign-in failed: ${result.type}`);
  }

  const params = parseCallbackQuery(result.url);
  const err = params.get('error');
  if (err) {
    const desc = params.get('error_description');
    throw new OAuthError(desc ? `${err}: ${desc}` : err);
  }
  if (params.get('state') !== state) {
    throw new OAuthError('State mismatch');
  }
  const code = params.get('code');
  if (!code) throw new OAuthError('Authorization response missing code');

  return exchangeCodeForTokens(metadata.tokenEndpoint, code, verifier, client);
}

async function exchangeCodeForTokens(
  tokenEndpoint: string,
  code: string,
  verifier: string,
  client: PkceClient,
): Promise<OAuthTokens> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: HANDOFF_REDIRECT_URI,
    client_id: client.clientId,
    code_verifier: verifier,
  });
  if (client.clientSecret) body.set('client_secret', client.clientSecret);
  const response = await secureFetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new OAuthError(`Token exchange failed: ${response.status}`);
  }
  const data = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
  if (!data.access_token) {
    throw new OAuthError('Token response missing access_token');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? undefined,
    expiresAt: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    tokenEndpoint,
    clientId: client.clientId,
    clientSecret: client.clientSecret,
  };
}

function buildAuthorizationUrl(endpoint: string, params: Record<string, string>): string {
  const url = new URL(endpoint);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

function parseCallbackQuery(url: string): URLSearchParams {
  const queryIdx = url.indexOf('?');
  if (queryIdx === -1) return new URLSearchParams();
  // The IdP may append a fragment (some send `?code=…#`); strip it.
  const tail = url.slice(queryIdx + 1);
  const hashIdx = tail.indexOf('#');
  return new URLSearchParams(hashIdx === -1 ? tail : tail.slice(0, hashIdx));
}

function mergeScopes(supported: string[] | undefined): string[] {
  const out = new Set(DEFAULT_SCOPES);
  if (supported) {
    for (const s of supported) {
      if (s.startsWith('urn:ietf:params:jmap:')) out.add(s);
    }
  }
  return [...out];
}

// ── randomness ──────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

function randomState(): string {
  const bytes = randomBytes(16);
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

// RFC 7636 §4.1 — 43–128 chars from the unreserved set. 64 chars of
// base64url from 48 random bytes is comfortably inside that range.
function randomCodeVerifier(): string {
  return base64UrlEncode(randomBytes(48));
}

function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
  // React Native ships `btoa`/`atob` polyfills via Hermes; standard base64
  // then translated to the URL-safe alphabet without padding.
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  // eslint-disable-next-line no-undef
  const b64 = typeof btoa !== 'undefined'
    // eslint-disable-next-line no-undef
    ? btoa(bin)
    : Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

WebBrowser.maybeCompleteAuthSession();
