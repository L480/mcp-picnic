import { Response } from "express"
import { randomUUID, randomBytes, timingSafeEqual } from "crypto"
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js"
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js"
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js"
import {
  InvalidGrantError,
  InvalidTokenError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js"

/**
 * Configuration for the static-token OAuth provider.
 */
export interface StaticTokenOAuthOptions {
  /** The shared secret token that gates access to the MCP server. */
  authToken: string
  /** Absolute URL of the authorization endpoint, used as the login form target. */
  authorizeEndpoint: string
  /** RFC 8707 resource identifier advertised for issued tokens. */
  resource?: string
  /** Lifetime of issued access tokens in seconds (default: 30 days). */
  accessTokenTtlSeconds?: number
  /** Lifetime of an authorization code in seconds (default: 5 minutes). */
  authorizationCodeTtlSeconds?: number
  /** Human readable name displayed on the login page. */
  serverName?: string
}

interface StoredAuthorizationCode {
  clientId: string
  codeChallenge: string
  redirectUri: string
  scopes: string[]
  resource?: string
  expiresAt: number
}

interface StoredRefreshToken {
  clientId: string
  scopes: string[]
  resource?: string
}

/**
 * Escapes a string for safe inclusion inside an HTML attribute or text node.
 */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

/**
 * Base64url-encodes a buffer without padding, suitable for opaque tokens.
 */
function base64url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/**
 * An OAuth 2.1 server provider that wraps a single static shared token.
 *
 * Claude's custom connector UI only speaks OAuth 2.0 (dynamic client
 * registration + authorization code + PKCE); it offers no field for pasting a
 * static bearer token. This provider implements just enough of the OAuth flow
 * for that UI to succeed: the user proves knowledge of the shared
 * `HTTP_AUTH_TOKEN` on a small login page during the authorization step, and in
 * return receives a normal OAuth access token that is sent as
 * `Authorization: Bearer <token>` on every subsequent MCP request.
 */
export class StaticTokenOAuthProvider implements OAuthServerProvider {
  private readonly authToken: string
  private readonly authTokenBuffer: Buffer
  private readonly authorizeEndpoint: string
  private readonly resource?: string
  private readonly accessTokenTtlSeconds: number
  private readonly authorizationCodeTtlSeconds: number
  private readonly serverName: string

  private readonly clients = new Map<string, OAuthClientInformationFull>()
  private readonly authorizationCodes = new Map<string, StoredAuthorizationCode>()
  private readonly accessTokens = new Map<string, AuthInfo>()
  private readonly refreshTokens = new Map<string, StoredRefreshToken>()

  constructor(options: StaticTokenOAuthOptions) {
    this.authToken = options.authToken
    this.authTokenBuffer = Buffer.from(options.authToken)
    this.authorizeEndpoint = options.authorizeEndpoint
    this.resource = options.resource
    this.accessTokenTtlSeconds = options.accessTokenTtlSeconds ?? 30 * 24 * 60 * 60
    this.authorizationCodeTtlSeconds = options.authorizationCodeTtlSeconds ?? 5 * 60
    this.serverName = options.serverName ?? "MCP Picnic"
  }

  public readonly clientsStore: OAuthRegisteredClientsStore = {
    getClient: (clientId: string) => this.clients.get(clientId),
    registerClient: (client) => {
      const clientId = randomUUID()
      const full: OAuthClientInformationFull = {
        ...client,
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
      }
      this.clients.set(clientId, full)
      return full
    },
  }

  /**
   * Constant-time comparison of a candidate token against the shared secret.
   */
  private isValidStaticToken(token: string | undefined): boolean {
    if (typeof token !== "string") {
      return false
    }
    const provided = Buffer.from(token)
    if (provided.length !== this.authTokenBuffer.length) {
      return false
    }
    return timingSafeEqual(provided, this.authTokenBuffer)
  }

  /**
   * Renders the login page shown during the authorization step. All OAuth
   * parameters are carried through as hidden fields so the POST re-enters the
   * standard authorization handler with the submitted token attached.
   */
  private renderLoginPage(params: AuthorizationParams, client: OAuthClientInformationFull, error?: string): string {
    const hidden = (name: string, value: string | undefined) =>
      value === undefined ? "" : `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`

    const clientLabel = client.client_name ? escapeHtml(client.client_name) : "an MCP client"
    const errorBlock = error
      ? `<p class="error" role="alert">${escapeHtml(error)}</p>`
      : ""

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Connect to ${escapeHtml(this.serverName)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
    min-height: 100vh; display: grid; place-items: center; background: #f5f5f7; color: #1d1d1f; }
  @media (prefers-color-scheme: dark) { body { background: #1c1c1e; color: #f5f5f7; } .card { background: #2c2c2e !important; } input { background: #1c1c1e !important; color: #f5f5f7 !important; border-color: #48484a !important; } }
  .card { background: #fff; padding: 2rem; border-radius: 14px; box-shadow: 0 10px 40px rgba(0,0,0,.12);
    width: min(92vw, 380px); box-sizing: border-box; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  p { margin: 0 0 1rem; color: #6e6e73; font-size: .9rem; line-height: 1.4; }
  label { display: block; font-size: .85rem; font-weight: 600; margin-bottom: .4rem; }
  input[type=password] { width: 100%; padding: .7rem .8rem; font-size: 1rem; border: 1px solid #d2d2d7;
    border-radius: 9px; box-sizing: border-box; }
  button { margin-top: 1.1rem; width: 100%; padding: .75rem; font-size: 1rem; font-weight: 600;
    color: #fff; background: #0071e3; border: 0; border-radius: 9px; cursor: pointer; }
  button:hover { background: #0077ed; }
  .error { color: #d70015; font-weight: 600; }
</style>
</head>
<body>
  <form class="card" method="post" action="${escapeHtml(this.authorizeEndpoint)}">
    <h1>Connect to ${escapeHtml(this.serverName)}</h1>
    <p>${clientLabel} wants to connect. Enter the access token to authorize.</p>
    ${errorBlock}
    <label for="mcp_auth_token">Access token</label>
    <input id="mcp_auth_token" name="mcp_auth_token" type="password" autocomplete="off" autofocus required />
    ${hidden("response_type", "code")}
    ${hidden("client_id", client.client_id)}
    ${hidden("redirect_uri", params.redirectUri)}
    ${hidden("code_challenge", params.codeChallenge)}
    ${hidden("code_challenge_method", "S256")}
    ${hidden("scope", params.scopes && params.scopes.length > 0 ? params.scopes.join(" ") : undefined)}
    ${hidden("state", params.state)}
    ${hidden("resource", params.resource ? params.resource.href : undefined)}
    <button type="submit">Connect</button>
  </form>
</body>
</html>`
  }

  /**
   * Handles the authorization endpoint. On the initial GET a login page is
   * rendered; once the correct token is submitted an authorization code is
   * issued and the user agent is redirected back to the client.
   */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const req = res.req as { body?: Record<string, unknown>; query?: Record<string, unknown> }
    const submitted =
      (req?.body?.mcp_auth_token as string | undefined) ?? (req?.query?.mcp_auth_token as string | undefined)

    // No token submitted yet: show the login form.
    if (typeof submitted !== "string" || submitted.length === 0) {
      res.status(200).setHeader("Content-Type", "text/html; charset=utf-8")
      res.send(this.renderLoginPage(params, client))
      return
    }

    // Token submitted but invalid: re-render the form with an error.
    if (!this.isValidStaticToken(submitted)) {
      res.status(401).setHeader("Content-Type", "text/html; charset=utf-8")
      res.send(this.renderLoginPage(params, client, "Invalid access token. Please try again."))
      return
    }

    // Valid token: issue an authorization code bound to this client + PKCE challenge.
    const code = base64url(randomBytes(32))
    this.authorizationCodes.set(code, {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      scopes: params.scopes ?? [],
      resource: params.resource?.href,
      expiresAt: Date.now() + this.authorizationCodeTtlSeconds * 1000,
    })

    const redirectUrl = new URL(params.redirectUri)
    redirectUrl.searchParams.set("code", code)
    if (params.state !== undefined) {
      redirectUrl.searchParams.set("state", params.state)
    }
    res.redirect(302, redirectUrl.href)
  }

  /**
   * Returns the PKCE challenge stored for an authorization code so the SDK can
   * validate the code verifier during token exchange.
   */
  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const stored = this.authorizationCodes.get(authorizationCode)
    if (!stored || stored.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code")
    }
    return stored.codeChallenge
  }

  /**
   * Exchanges a validated authorization code for a fresh access/refresh token pair.
   */
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const stored = this.authorizationCodes.get(authorizationCode)
    if (!stored || stored.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code")
    }
    // Authorization codes are single-use.
    this.authorizationCodes.delete(authorizationCode)

    if (stored.expiresAt < Date.now()) {
      throw new InvalidGrantError("Authorization code has expired")
    }
    if (redirectUri !== undefined && redirectUri !== stored.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request")
    }

    return this.issueTokens(client.client_id, stored.scopes, stored.resource)
  }

  /**
   * Exchanges a refresh token for a new access/refresh token pair.
   */
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const stored = this.refreshTokens.get(refreshToken)
    if (!stored || stored.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid refresh token")
    }
    // Rotate the refresh token.
    this.refreshTokens.delete(refreshToken)

    const grantedScopes = scopes && scopes.length > 0 ? scopes : stored.scopes
    return this.issueTokens(client.client_id, grantedScopes, stored.resource)
  }

  /**
   * Issues a new access token (and rotating refresh token) for a client.
   */
  private issueTokens(clientId: string, scopes: string[], resource?: string): OAuthTokens {
    const accessToken = base64url(randomBytes(32))
    const refreshToken = base64url(randomBytes(32))
    const expiresAt = Math.floor(Date.now() / 1000) + this.accessTokenTtlSeconds

    this.accessTokens.set(accessToken, {
      token: accessToken,
      clientId,
      scopes,
      expiresAt,
      resource: resource ? new URL(resource) : this.resource ? new URL(this.resource) : undefined,
    })
    this.refreshTokens.set(refreshToken, { clientId, scopes, resource })

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: this.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope: scopes.length > 0 ? scopes.join(" ") : undefined,
    }
  }

  /**
   * Verifies an issued access token, returning its auth info or throwing.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const authInfo = this.getValidAccessToken(token)
    if (!authInfo) {
      throw new InvalidTokenError("Invalid or expired access token")
    }
    return authInfo
  }

  /**
   * Non-throwing lookup of a valid, unexpired access token. Returns `undefined`
   * when the token is unknown or expired (and prunes expired entries).
   */
  public getValidAccessToken(token: string): AuthInfo | undefined {
    const authInfo = this.accessTokens.get(token)
    if (!authInfo) {
      return undefined
    }
    if (authInfo.expiresAt !== undefined && authInfo.expiresAt < Math.floor(Date.now() / 1000)) {
      this.accessTokens.delete(token)
      return undefined
    }
    return authInfo
  }

  /**
   * Revokes an access or refresh token.
   */
  async revokeToken(
    _client: OAuthClientInformationFull,
    request: { token: string; token_type_hint?: string },
  ): Promise<void> {
    if (!request.token) {
      throw new ServerError("Missing token to revoke")
    }
    this.accessTokens.delete(request.token)
    this.refreshTokens.delete(request.token)
  }
}
