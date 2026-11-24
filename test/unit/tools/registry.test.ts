import { describe, it, expect, beforeEach, vi } from "vitest"
import { z } from "zod"
import { toolRegistry, ToolDefinition, ToolResult } from "../../../src/tools/registry.js"
import { ToolError, ErrorCode } from "../../../src/types/errors.js"

describe("ToolRegistry", () => {
  beforeEach(() => {
    // Clear registry before each test
    toolRegistry["tools"].clear()
  })

  describe("register", () => {
    it("should register a tool definition", () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "test-tool",
        description: "A test tool",
        inputSchema: z.object({ input: z.string() }),
        outputSchema: z.string(),
        handler: async (args) => `Hello ${args.input}`,
      }

      toolRegistry.register(mockTool)

      expect(toolRegistry["tools"].has("test-tool")).toBe(true)
      expect(toolRegistry["tools"].get("test-tool")?.name).toBe("test-tool")
    })

    it("should register a tool without output schema", () => {
      const mockTool: ToolDefinition<{ input: string }, unknown> = {
        name: "simple-tool",
        description: "A simple tool",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => args.input,
      }

      toolRegistry.register(mockTool)

      const registered = toolRegistry["tools"].get("simple-tool")
      expect(registered?.outputSchema).toBeUndefined()
    })

    it("should register a tool with prompts", () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "tool-with-prompts",
        description: "A tool with prompts",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => args.input,
        prompts: ["prompt1", "prompt2"],
      }

      toolRegistry.register(mockTool)

      const registered = toolRegistry["tools"].get("tool-with-prompts")
      expect(registered?.prompts).toEqual(["prompt1", "prompt2"])
    })
  })

  describe("getToolDefinitions", () => {
    it("should return empty object when no tools registered", () => {
      const definitions = toolRegistry.getToolDefinitions()
      expect(definitions).toEqual({})
    })

    it("should return tool definitions with uppercase keys", () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "test-tool",
        description: "A test tool",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => args.input,
      }

      toolRegistry.register(mockTool)

      const definitions = toolRegistry.getToolDefinitions()
      expect(definitions).toHaveProperty("TEST-TOOL")
      expect(definitions["TEST-TOOL"]).toMatchObject({
        name: "test-tool",
        description: "A test tool",
        inputSchema: expect.any(Object),
      })
    })
  })

  describe("input JSON schema contract", () => {
    const expectedSchema = {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      properties: {
        query: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 20, default: 5 },
        filter: {
          type: "object",
          properties: { status: { type: "string" } },
          required: ["status"],
          additionalProperties: false,
        },
      },
      required: ["query"],
      additionalProperties: false,
    }

    beforeEach(() => {
      toolRegistry.register({
        name: "contract-tool",
        description: "Schema contract",
        inputSchema: z.object({
          query: z.string(),
          limit: z.number().int().min(1).max(20).default(5),
          filter: z.object({ status: z.string() }).optional(),
        }),
        handler: async () => "ok",
      })
    })

    it("advertises draft-07, optional defaulted fields and closed nested objects in getToolsList", () => {
      expect(toolRegistry.getToolsList()[0].inputSchema).toEqual(expectedSchema)
    })

    it("advertises the same schema in getToolDefinitions", () => {
      const definitions = toolRegistry.getToolDefinitions() as Record<
        string,
        { inputSchema: unknown }
      >
      expect(definitions["CONTRACT-TOOL"].inputSchema).toEqual(expectedSchema)
    })
  })

  describe("getToolsList", () => {
    it("should return empty array when no tools registered", () => {
      const list = toolRegistry.getToolsList()
      expect(list).toEqual([])
    })

    it("should return array of tool definitions", () => {
      const mockTool1: ToolDefinition<{ input: string }, string> = {
        name: "tool1",
        description: "First tool",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => args.input,
      }

      const mockTool2: ToolDefinition<{ value: number }, number> = {
        name: "tool2",
        description: "Second tool",
        inputSchema: z.object({ value: z.number() }),
        handler: async (args) => args.value * 2,
      }

      toolRegistry.register(mockTool1)
      toolRegistry.register(mockTool2)

      const list = toolRegistry.getToolsList()
      expect(list).toHaveLength(2)
      expect(list.map((t) => t.name)).toContain("tool1")
      expect(list.map((t) => t.name)).toContain("tool2")
    })
  })

  describe("executeTool", () => {
    it("should execute a tool successfully", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "test-tool",
        description: "A test tool",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => `Hello ${args.input}`,
      }

      toolRegistry.register(mockTool)

      const result = await toolRegistry.executeTool("test-tool", { input: "World" })
      expect(result).toEqual({
        content: [{ type: "text", text: "Hello World" }],
      })
    })

    it("should throw ToolError for unknown tool", async () => {
      await expect(toolRegistry.executeTool("unknown-tool", {})).rejects.toThrow(ToolError)
      await expect(toolRegistry.executeTool("unknown-tool", {})).rejects.toThrow(
        "Tool 'unknown-tool' not found",
      )
    })

    it("should validate input with Zod schema", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "validation-tool",
        description: "A tool with validation",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => args.input,
      }

      toolRegistry.register(mockTool)

      await expect(toolRegistry.executeTool("validation-tool", { input: 123 })).rejects.toThrow(
        ToolError,
      )
      await expect(toolRegistry.executeTool("validation-tool", { input: 123 })).rejects.toThrow(
        "Invalid input",
      )
    })

    it("should handle tool execution errors", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "error-tool",
        description: "A tool that throws an error",
        inputSchema: z.object({ input: z.string() }),
        handler: async () => {
          throw new Error("Tool execution failed")
        },
      }

      toolRegistry.register(mockTool)

      await expect(toolRegistry.executeTool("error-tool", { input: "test" })).rejects.toThrow(
        ToolError,
      )
    })

    it("should validate output with output schema", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "output-validation-tool",
        description: "A tool with output validation",
        inputSchema: z.object({ input: z.string() }),
        outputSchema: z.string(),
        handler: async () => 123 as any, // Return wrong type
      }

      toolRegistry.register(mockTool)

      await expect(
        toolRegistry.executeTool("output-validation-tool", { input: "test" }),
      ).rejects.toThrow(ToolError)
    })

    it("should format string result correctly", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "string-tool",
        description: "A tool that returns a string",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => `Result: ${args.input}`,
      }

      toolRegistry.register(mockTool)

      const result = await toolRegistry.executeTool("string-tool", { input: "test" })
      expect(result).toEqual({
        content: [{ type: "text", text: "Result: test" }],
      })
    })

    it("should format object result correctly", async () => {
      const mockTool: ToolDefinition<{ input: string }, object> = {
        name: "object-tool",
        description: "A tool that returns an object",
        inputSchema: z.object({ input: z.string() }),
        handler: async (args) => ({ result: args.input, status: "success" }),
      }

      toolRegistry.register(mockTool)

      const result = await toolRegistry.executeTool("object-tool", { input: "test" })
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({ result: "test", status: "success" }, null, 2),
          },
        ],
      })
    })

    it("should format primitive result correctly", async () => {
      const mockTool: ToolDefinition<{ input: number }, number> = {
        name: "number-tool",
        description: "A tool that returns a number",
        inputSchema: z.object({ input: z.number() }),
        handler: async (args) => args.input * 2,
      }

      toolRegistry.register(mockTool)

      const result = await toolRegistry.executeTool("number-tool", { input: 5 })
      expect(result).toEqual({
        content: [{ type: "text", text: "10" }],
      })
    })

    it("should handle missing required arguments", async () => {
      const mockTool: ToolDefinition<{ required: string; optional?: string }, string> = {
        name: "required-args-tool",
        description: "A tool with required arguments",
        inputSchema: z.object({
          required: z.string(),
          optional: z.string().optional(),
        }),
        handler: async (args) => args.required,
      }

      toolRegistry.register(mockTool)

      await expect(toolRegistry.executeTool("required-args-tool", {})).rejects.toThrow(ToolError)
    })

    it("should handle complex validation errors", async () => {
      const mockTool: ToolDefinition<{ email: string; age: number }, string> = {
        name: "complex-validation-tool",
        description: "A tool with complex validation",
        inputSchema: z.object({
          email: z.string().email(),
          age: z.number().min(0).max(120),
        }),
        handler: async (args) => `${args.email} is ${args.age} years old`,
      }

      toolRegistry.register(mockTool)

      await expect(
        toolRegistry.executeTool("complex-validation-tool", {
          email: "invalid-email",
          age: -5,
        }),
      ).rejects.toThrow(ToolError)
    })

    it("should wrap unexpected errors", async () => {
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "unexpected-error-tool",
        description: "A tool that throws unexpected error",
        inputSchema: z.object({ input: z.string() }),
        handler: async () => {
          throw "String error" // Non-Error object
        },
      }

      toolRegistry.register(mockTool)

      await expect(
        toolRegistry.executeTool("unexpected-error-tool", { input: "test" }),
      ).rejects.toThrow(ToolError)
    })
  })

  describe("error handling", () => {
    it("should preserve MCP errors", async () => {
      const mcpError = new ToolError(ErrorCode.TOOL_EXECUTION_FAILED, "Custom MCP error")
      const mockTool: ToolDefinition<{ input: string }, string> = {
        name: "mcp-error-tool",
        description: "A tool that throws MCP error",
        inputSchema: z.object({ input: z.string() }),
        handler: async () => {
          throw mcpError
        },
      }

      toolRegistry.register(mockTool)

      await expect(toolRegistry.executeTool("mcp-error-tool", { input: "test" })).rejects.toBe(
        mcpError,
      )
    })

    it("should include validation error details", async () => {
      const mockTool: ToolDefinition<{ count: number }, string> = {
        name: "validation-details-tool",
        description: "A tool for testing validation details",
        inputSchema: z.object({ count: z.number().positive() }),
        handler: async (args) => `Count: ${args.count}`,
      }

      toolRegistry.register(mockTool)

      const error = await toolRegistry
        .executeTool("validation-details-tool", { count: -1 })
        .catch((e: unknown) => e)

      expect(error).toBeInstanceOf(ToolError)
      expect((error as ToolError).details).toMatchObject({
        toolName: "validation-details-tool",
        validationErrors: expect.any(Array),
      })
      // Details end up in the logs, so the raw arguments must not be part of them.
      expect((error as ToolError).details).not.toHaveProperty("providedArgs")
      expect((error as ToolError).details?.validationErrors).toEqual([
        { code: "too_small", path: ["count"], message: expect.any(String) },
      ])
    })
  })
})
