import { z } from "zod"
import path from "path"
import os from "os"
import dotenv from "dotenv"

dotenv.config()

const defaultSessionFile = path.join(os.homedir(), ".picnic-session.json")

const configSchema = z.object({
  PICNIC_USERNAME: z.string(),
  PICNIC_PASSWORD: z.string(),
  PICNIC_COUNTRY_CODE: z.enum(["NL", "DE"]).default("NL"),
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
  PICNIC_SESSION_FILE: z.string().default(defaultSessionFile),
})

export const config = configSchema.parse(process.env)
