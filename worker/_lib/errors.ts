export type ErrorCode =
  | 'BAD_REQUEST'
  | 'INVALID_INPUT'
  | 'INVALID_URL'
  | 'TARGET_NOT_ALLOWED'
  | 'DOES_NOT_RESOLVE'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'METHOD_NOT_ALLOWED'
  | 'PAYLOAD_TOO_LARGE'
  | 'NOT_CONFIGURED'
  | 'PROVIDER_BUDGET'
  | 'UPSTREAM_ERROR'
  | 'UPSTREAM_TIMEOUT'
  | 'INTERNAL';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: ErrorCode,
    message: string,
    public readonly headers: Record<string, string> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export const badInput = (message: string) => new ApiError(400, 'INVALID_INPUT', message);
export const upstream = (message: string) => new ApiError(502, 'UPSTREAM_ERROR', message);
