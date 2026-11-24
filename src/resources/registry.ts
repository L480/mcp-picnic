import { z } from "zod"

export interface ResourceDefinition<TArgs = unknown> {
  uri: string
  name: string
  description?: string
  mimeType?: string
  argsSchema?: z.ZodSchema<TArgs>
  handler: (args?: TArgs) => Promise<ResourceContent>
}

export interface ResourceContent {
  contents: Array<{
    uri: string
    mimeType?: string
    text?: string
    blob?: string
  }>
}

// Type-erased version for storage
interface StoredResourceDefinition {
  uri: string
  name: string
  description?: string
  mimeType?: string
  argsSchema?: z.ZodSchema<unknown>
  handler: (args?: unknown) => Promise<ResourceContent>
}

class ResourceRegistry {
  private resources = new Map<string, StoredResourceDefinition>()

  register<TArgs>(resource: ResourceDefinition<TArgs>) {
    this.resources.set(resource.uri, resource as StoredResourceDefinition)
  }

  getResourceDefinitions() {
    const definitions: Record<string, unknown> = {}
    for (const [uri, resource] of this.resources) {
      const key = uri.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()
      definitions[key] = {
        uri: resource.uri,
        name: resource.name,
        description: resource.description,
        mimeType: resource.mimeType,
      }
    }
    return definitions
  }

  getResourcesList() {
    return Array.from(this.resources.values()).map((resource) => ({
      uri: resource.uri,
      name: resource.name,
      description: resource.description,
      mimeType: resource.mimeType,
    }))
  }

  async readResource(uri: string, args?: unknown): Promise<ResourceContent> {
    const resource = this.resources.get(uri)
    if (!resource) {
      throw new Error(`Unknown resource: ${uri}`)
    }

    try {
      // Validate args if schema is provided
      let validatedArgs = args
      if (resource.argsSchema && args) {
        validatedArgs = resource.argsSchema.parse(args)
      }

      return await resource.handler(validatedArgs)
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(
          `Invalid arguments: ${error.issues.map((e) => `${e.path.join(".")}: ${e.message}`).join(", ")}`,
        )
      }
      throw error
    }
  }

  hasResource(uri: string): boolean {
    return this.resources.has(uri)
  }

  getResourceUris(): string[] {
    return Array.from(this.resources.keys())
  }
}

export const resourceRegistry = new ResourceRegistry()
