/**
 * Error types for @rubric/verify.
 *
 * Errors thrown by this library are limited to:
 *   - VerificationInputError: malformed input that cannot be coerced to a verdict
 *   - AnchorFetchError: network failure during anchor confirmation
 *   - SpecConformanceError: invariant violation in the verification path itself
 *
 * Cryptographic-failure conditions (bad signature, wrong key, mismatched root)
 * do NOT throw — they produce `verified: false` with diagnostic detail.
 */

export class RubricVerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Input is structurally invalid (missing required field, wrong type, etc.). */
export class VerificationInputError extends RubricVerifyError {
  constructor(message: string) {
    super(`VerificationInputError: ${message}`);
  }
}

/** Network or RPC failure when fetching anchor data. Caller may retry. */
export class AnchorFetchError extends RubricVerifyError {
  public readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(`AnchorFetchError: ${message}`);
    this.cause = cause;
  }
}

/**
 * Invariant violation in the verification logic itself. Should never fire
 * in conforming code. If you see this, please file an issue.
 */
export class SpecConformanceError extends RubricVerifyError {
  constructor(message: string) {
    super(`SpecConformanceError: ${message}`);
  }
}
