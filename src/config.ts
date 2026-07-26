import { z } from "zod"
import path from "path"
import os from "os"
import dotenv from "dotenv"

dotenv.config()

const defaultSessionFile = path.join(os.homedir(), ".picnic-session.json")
const defaultDeviceFile = path.join(os.homedir(), ".picnic-device.json")

const configSchema = z.object({
  PICNIC_USERNAME: z.string(),
  PICNIC_PASSWORD: z.string(),
  PICNIC_COUNTRY_CODE: z.enum(["NL", "DE", "FR"]).default("NL"),
  PICNIC_API_VERSION: z.string().default("15"),
  PICNIC_DEVICE_ID: z.string().optional(),
  PICNIC_DEVICE_FILE: z.string().default(defaultDeviceFile),
  PICNIC_AGENT: z.string().optional(),
  ENABLE_HTTP_SERVER: z
    .string()
    .transform((val) => val === "true")
    .default("false"),
  HTTP_PORT: z
    .string()
    .transform((val) => parseInt(val, 10))
    .default("3000"),
  HTTP_HOST: z.string().default("localhost"),
  HTTP_AUTH_TOKEN: z.string().optional(),
  HTTP_AUTH_HEADER_NAME: z.string().default("x-mcp-token"),
  // Enable an OAuth 2.1 wrapper around HTTP_AUTH_TOKEN so clients that only
  // support OAuth (e.g. Claude's custom connectors) can authenticate. Enabled
  // by default whenever HTTP_AUTH_TOKEN is set.
  HTTP_OAUTH_ENABLED: z
    .string()
    .transform((val) => val !== "false")
    .default("true"),
  // Public HTTPS base URL the server is reachable at (e.g. https://picnic.example.com).
  // Required for the OAuth flow when the server is reached over anything other
  // than localhost, because OAuth issuer URLs must be HTTPS.
  HTTP_PUBLIC_URL: z.string().url().optional(),
  // Express "trust proxy" setting. Required when running behind a reverse proxy
  // (e.g. nginx/Traefik/Caddy in front of the container) so that client IPs are
  // read from X-Forwarded-For and the rate limiter does not error. Accepts a
  // boolean ("true"/"false"), a number of hops ("1"), or a preset/subnet string
  // ("loopback", "10.0.0.0/8", ...). Defaults to trusting the first hop.
  HTTP_TRUST_PROXY: z
    .string()
    .default("1")
    .transform((val): boolean | number | string => {
      if (val === "true") return true
      if (val === "false" || val === "") return false
      if (/^\d+$/.test(val)) return parseInt(val, 10)
      return val
    }),
  // How long an idle MCP session is kept alive before it is cleaned up
  // (refreshed on every request). Set to "0" to disable idle expiry and keep
  // sessions open indefinitely. Defaults to 12 hours.
  HTTP_SESSION_TIMEOUT_MS: z
    .string()
    .transform((val) => parseInt(val, 10))
    .default(String(12 * 60 * 60 * 1000)),
  PICNIC_SESSION_FILE: z.string().default(defaultSessionFile),
})

export const config = configSchema.parse(process.env)
