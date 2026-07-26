/**
 * Custom error types for MCP server operations
 */

export enum ErrorCode {
  // Transport errors
  TRANSPORT_CONNECTION_FAILED = "TRANSPORT_CONNECTION_FAILED",
  TRANSPORT_TIMEOUT = "TRANSPORT_TIMEOUT",
  TRANSPORT_INVALID_SESSION = "TRANSPORT_INVALID_SESSION",
  TRANSPORT_SESSION_EXPIRED = "TRANSPORT_SESSION_EXPIRED",
  TRANSPORT_RATE_LIMITED = "TRANSPORT_RATE_LIMITED",
  SESSION_LIMIT_EXCEEDED = "SESSION_LIMIT_EXCEEDED",

  // Tool errors
  TOOL_NOT_FOUND = "TOOL_NOT_FOUND",
  TOOL_VALIDATION_FAILED = "TOOL_VALIDATION_FAILED",
  TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED",
  TOOL_TIMEOUT = "TOOL_TIMEOUT",

  // Prompt errors
  PROMPT_NOT_FOUND = "PROMPT_NOT_FOUND",
  PROMPT_VALIDATION_FAILED = "PROMPT_VALIDATION_FAILED",
  PROMPT_EXECUTION_FAILED = "PROMPT_EXECUTION_FAILED",

  // Resource errors
  RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND",
  RESOURCE_ACCESS_DENIED = "RESOURCE_ACCESS_DENIED",
  RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE",

  // Server errors
  SERVER_INITIALIZATION_FAILED = "SERVER_INITIALIZATION_FAILED",
  SERVER_SHUTDOWN_FAILED = "SERVER_SHUTDOWN_FAILED",
  SERVER_OVERLOADED = "SERVER_OVERLOADED",

  // Generic errors
  INVALID_REQUEST = "INVALID_REQUEST",
  INTERNAL_ERROR = "INTERNAL_ERROR",
  CONFIGURATION_ERROR = "CONFIGURATION_ERROR",
}

export class MCPError extends Error {
  public readonly code: ErrorCode
  public readonly statusCode: number
  public readonly details?: Record<string, unknown>
  public readonly timestamp: string

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 500,
    details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = "MCPError"
    this.code = code
    this.statusCode = statusCode
    this.details = details
    this.timestamp = new Date().toISOString()

    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MCPError)
    }
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack,
    }
  }

  toMCPError() {
    return {
      code: this.getMCPErrorCode(),
      message: this.message,
      data: {
        errorCode: this.code,
        details: this.details,
        timestamp: this.timestamp,
      },
    }
  }

  private getMCPErrorCode(): number {
    // Map our error codes to JSON-RPC error codes
    switch (this.code) {
      case ErrorCode.INVALID_REQUEST:
      case ErrorCode.TOOL_VALIDATION_FAILED:
      case ErrorCode.PROMPT_VALIDATION_FAILED:
        return -32600 // Invalid Request
      case ErrorCode.TOOL_NOT_FOUND:
      case ErrorCode.PROMPT_NOT_FOUND:
      case ErrorCode.RESOURCE_NOT_FOUND:
        return -32601 // Method not found
      case ErrorCode.TOOL_EXECUTION_FAILED:
      case ErrorCode.PROMPT_EXECUTION_FAILED:
        return -32602 // Invalid params
      case ErrorCode.TRANSPORT_TIMEOUT:
      case ErrorCode.TOOL_TIMEOUT:
        return -32000 // Server error (timeout)
      case ErrorCode.TRANSPORT_RATE_LIMITED:
        return -32000 // Server error (rate limited)
      case ErrorCode.RESOURCE_ACCESS_DENIED:
        return -32000 // Server error (access denied)
      default:
        return -32603 // Internal error
    }
  }
}

export class TransportError extends MCPError {
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    const statusCode =
      code === ErrorCode.TRANSPORT_RATE_LIMITED
        ? 429
        : code === ErrorCode.TRANSPORT_INVALID_SESSION
          ? 400
          : code === ErrorCode.TRANSPORT_SESSION_EXPIRED
            ? 404
            : code === ErrorCode.TRANSPORT_TIMEOUT
              ? 408
              : 500
    super(code, message, statusCode, details)
    this.name = "TransportError"
  }
}

export class ToolError extends MCPError {
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    const statusCode =
      code === ErrorCode.TOOL_NOT_FOUND
        ? 404
        : code === ErrorCode.TOOL_VALIDATION_FAILED
          ? 400
          : code === ErrorCode.TOOL_TIMEOUT
            ? 408
            : 500
    super(code, message, statusCode, details)
    this.name = "ToolError"
  }
}

export class PromptError extends MCPError {
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    const statusCode =
      code === ErrorCode.PROMPT_NOT_FOUND
        ? 404
        : code === ErrorCode.PROMPT_VALIDATION_FAILED
          ? 400
          : 500
    super(code, message, statusCode, details)
    this.name = "PromptError"
  }
}

export class ResourceError extends MCPError {
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    const statusCode =
      code === ErrorCode.RESOURCE_NOT_FOUND
        ? 404
        : code === ErrorCode.RESOURCE_ACCESS_DENIED
          ? 403
          : 500
    super(code, message, statusCode, details)
    this.name = "ResourceError"
  }
}

/**
 * Utility functions for error handling
 */
export class ErrorUtils {
  /**
   * Safely extract error message from unknown error
   */
  static getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message
    }
    if (typeof error === "string") {
      return error
    }
    return "Unknown error occurred"
  }

  /**
   * Check if error is a specific MCP error type
   */
  static isMCPError(error: unknown): error is MCPError {
    return error instanceof MCPError
  }

  /**
   * Create a safe error response for clients
   */
  static createSafeErrorResponse(error: unknown, includeStack: boolean = false) {
    if (ErrorUtils.isMCPError(error)) {
      return {
        ...error.toMCPError(),
        ...(includeStack && { stack: error.stack }),
      }
    }

    return {
      code: -32603,
      message: ErrorUtils.getErrorMessage(error),
      data: {
        errorCode: ErrorCode.INTERNAL_ERROR,
        timestamp: new Date().toISOString(),
        ...(includeStack && error instanceof Error && { stack: error.stack }),
      },
    }
  }

  /**
   * Log error with appropriate level
   */
  static logError(error: unknown, context?: string) {
    const prefix = context ? `[${context}] ` : ""

    if (ErrorUtils.isMCPError(error)) {
      console.error(`${prefix}MCP Error [${error.code}]:`, error.message, error.details)
    } else if (error instanceof Error) {
      console.error(`${prefix}Error:`, error.message, error.stack)
    } else {
      console.error(`${prefix}Unknown error:`, error)
    }
  }

  /**
   * Wrap async function with error handling
   */
  static withErrorHandling<T extends unknown[], R>(
    fn: (...args: T) => Promise<R>,
    context?: string,
  ) {
    return async (...args: T): Promise<R> => {
      try {
        return await fn(...args)
      } catch (error) {
        ErrorUtils.logError(error, context)
        throw error
      }
    }
  }

  /**
   * Create timeout wrapper for promises
   */
  static withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorMessage: string = "Operation timed out",
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new MCPError(ErrorCode.TRANSPORT_TIMEOUT, errorMessage, 408))
        }, timeoutMs)
      }),
    ])
  }
}
