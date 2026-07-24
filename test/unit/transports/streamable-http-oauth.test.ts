import http from "http"
import { createHash, randomBytes } from "crypto"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { StreamableHttpServer } from "../../../src/transports/streamable-http"
import { createMCPServer } from "../../../src/utils/server-factory"

// Only mock the MCP server factory so no real Picnic connection is attempted.
// Crypto is intentionally NOT mocked here: the OAuth flow relies on real
// randomness and PKCE (SHA-256) hashing.
vi.mock("../../../src/utils/server-factory")

vi.mock("@modelcontextprotocol/sdk/server/streamableHttp.js", () => ({
  StreamableHTTPServerTransport: vi.fn().mockImplementation((options) => {
    const transport = {
      sessionId: "test-session-id",
      close: vi.fn().mockResolvedValue(undefined),
      onclose: undefined,
      handleRequest: vi.fn().mockResolvedValue(undefined),
    }
    if (options?.onsessioninitialized) {
      options.onsessioninitialized(transport.sessionId)
    }
    return transport
  }),
}))

interface HttpResult {
  statusCode: number
  headers: http.IncomingHttpHeaders
  body: string
}

function base64url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

describe("StreamableHttpServer OAuth flow", () => {
  let server: StreamableHttpServer
  let port: number

  const request = (
    path: string,
    options: {
      method?: string
      headers?: Record<string, string>
      body?: string
    } = {},
  ): Promise<HttpResult> =>
    new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port,
          path,
          method: options.method ?? "GET",
          headers: options.headers,
        },
        (response) => {
          let data = ""
          response.on("data", (chunk) => (data += chunk))
          response.on("end", () =>
            resolve({
              statusCode: response.statusCode!,
              headers: response.headers,
              body: data,
            }),
          )
        },
      )
      req.on("error", reject)
      if (options.body !== undefined) {
        req.write(options.body)
      }
      req.end()
    })

  const form = (data: Record<string, string>): string =>
    Object.entries(data)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&")

  beforeEach(async () => {
    vi.mocked(createMCPServer).mockReturnValue({
      server: { setRequestHandler: vi.fn(), connect: vi.fn().mockResolvedValue(undefined) },
      connect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    } as any)

    // publicUrl uses localhost so the SDK accepts the (non-HTTPS) issuer URL.
    // trustProxy mirrors the containerised-behind-a-reverse-proxy deployment.
    server = new StreamableHttpServer({
      port: 0,
      host: "localhost",
      authToken: "super-secret-token",
      publicUrl: "http://localhost",
      trustProxy: 1,
      enableRequestLogging: false,
    })
    await server.start()
    // @ts-expect-error - private property access for test
    const httpServer = server.server as http.Server
    port = (httpServer.address() as { port: number }).port
  })

  afterEach(async () => {
    if (server) {
      await server.stop().catch(() => {})
    }
    vi.restoreAllMocks()
  })

  it("advertises protected resource metadata for OAuth discovery", async () => {
    const res = await request("/.well-known/oauth-protected-resource/mcp")
    expect(res.statusCode).toBe(200)
    const body = JSON.parse(res.body)
    expect(body.authorization_servers).toContain("http://localhost/")
    expect(body.resource).toBe("http://localhost/mcp")
  })

  it("advertises authorization server metadata with the expected endpoints", async () => {
    const res = await request("/.well-known/oauth-authorization-server")
    expect(res.statusCode).toBe(200)
    const body = JSON.parse(res.body)
    expect(body.authorization_endpoint).toBe("http://localhost/authorize")
    expect(body.token_endpoint).toBe("http://localhost/token")
    expect(body.registration_endpoint).toBe("http://localhost/register")
    expect(body.code_challenge_methods_supported).toContain("S256")
  })

  it("returns 401 with a WWW-Authenticate challenge when unauthenticated", async () => {
    const res = await request("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    })
    expect(res.statusCode).toBe(401)
    expect(res.headers["www-authenticate"]).toContain("resource_metadata=")
    expect(res.headers["www-authenticate"]).toContain("oauth-protected-resource")
  })

  it("completes the full authorization-code + PKCE flow and issues a usable token", async () => {
    // 1. Dynamic client registration.
    const registerRes = await request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://localhost/callback"],
        token_endpoint_auth_method: "none",
        client_name: "Test Connector",
      }),
    })
    expect(registerRes.statusCode).toBe(201)
    const client = JSON.parse(registerRes.body)
    expect(client.client_id).toBeTruthy()

    // 2. PKCE parameters.
    const codeVerifier = base64url(randomBytes(32))
    const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest())

    // 3. Authorize with the correct shared token -> expect a redirect with a code.
    const authorizeRes = await request("/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: "http://localhost/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state: "xyz-state",
        mcp_auth_token: "super-secret-token",
      }),
    })
    expect(authorizeRes.statusCode).toBe(302)
    const location = new URL(authorizeRes.headers.location as string)
    expect(location.searchParams.get("state")).toBe("xyz-state")
    const code = location.searchParams.get("code")
    expect(code).toBeTruthy()

    // 4. Exchange the code for tokens.
    const tokenRes = await request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({
        grant_type: "authorization_code",
        code: code!,
        code_verifier: codeVerifier,
        client_id: client.client_id,
        redirect_uri: "http://localhost/callback",
      }),
    })
    expect(tokenRes.statusCode).toBe(200)
    const tokens = JSON.parse(tokenRes.body)
    expect(tokens.token_type).toBe("Bearer")
    expect(tokens.access_token).toBeTruthy()
    expect(tokens.refresh_token).toBeTruthy()

    // 5. Use the issued access token to reach a protected endpoint.
    const protectedRes = await request("/sessions", {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    expect(protectedRes.statusCode).toBe(200)

    // 6. Refresh token exchange yields a new usable access token.
    const refreshRes = await request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.client_id,
      }),
    })
    expect(refreshRes.statusCode).toBe(200)
    const refreshed = JSON.parse(refreshRes.body)
    expect(refreshed.access_token).toBeTruthy()

    const refreshedProtectedRes = await request("/sessions", {
      headers: { Authorization: `Bearer ${refreshed.access_token}` },
    })
    expect(refreshedProtectedRes.statusCode).toBe(200)
  })

  it("rejects the authorization request when the shared token is wrong", async () => {
    const registerRes = await request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["http://localhost/callback"],
        token_endpoint_auth_method: "none",
      }),
    })
    const client = JSON.parse(registerRes.body)

    const authorizeRes = await request("/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: "http://localhost/callback",
        code_challenge: "challenge",
        code_challenge_method: "S256",
        mcp_auth_token: "wrong-token",
      }),
    })

    expect(authorizeRes.statusCode).toBe(401)
    expect(authorizeRes.headers.location).toBeUndefined()
  })

  it("still accepts the raw shared token as a bearer token (backwards compatible)", async () => {
    const res = await request("/sessions", {
      headers: { Authorization: "Bearer super-secret-token" },
    })
    expect(res.statusCode).toBe(200)
  })

  it("handles the token endpoint behind a reverse proxy (X-Forwarded-For)", async () => {
    // Regression for ERR_ERL_UNEXPECTED_X_FORWARDED_FOR: with trust proxy on,
    // the SDK rate limiter must not reject forwarded requests during the OAuth
    // token exchange (which previously broke the flow with a 500).
    const proxyHeaders = { "X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https" }

    const registerRes = await request("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...proxyHeaders },
      body: JSON.stringify({
        redirect_uris: ["http://localhost/callback"],
        token_endpoint_auth_method: "none",
      }),
    })
    expect(registerRes.statusCode).toBe(201)
    const client = JSON.parse(registerRes.body)

    const codeVerifier = base64url(randomBytes(32))
    const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest())

    const authorizeRes = await request("/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...proxyHeaders },
      body: form({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: "http://localhost/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        mcp_auth_token: "super-secret-token",
      }),
    })
    expect(authorizeRes.statusCode).toBe(302)
    const code = new URL(authorizeRes.headers.location as string).searchParams.get("code")

    const tokenRes = await request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...proxyHeaders },
      body: form({
        grant_type: "authorization_code",
        code: code!,
        code_verifier: codeVerifier,
        client_id: client.client_id,
        redirect_uri: "http://localhost/callback",
      }),
    })

    // Must succeed rather than 500 with a rate-limiter validation error.
    expect(tokenRes.statusCode).toBe(200)
    expect(JSON.parse(tokenRes.body).access_token).toBeTruthy()
  })
})
