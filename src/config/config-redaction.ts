/**
 * Redaction helpers for the admin runtime-configuration endpoint.
 *
 * The denylist below is the single source of truth for which `AppConfig`
 * fields must never be exposed over the wire. A companion test asserts that
 * every `AppConfig` field whose name looks secret-shaped (see
 * `SECRET_SHAPED_FIELD_PATTERN`) is present in the denylist, so a newly-added
 * secret field cannot silently leak.
 */

import { AppConfig } from './configuration';

/**
 * Heuristic for "this field name probably holds a secret".
 *
 * Mirrors the convention used by `src/soroban/redaction.ts` so we do not end
 * up with two competing redaction conventions in the codebase.
 */
export const SECRET_SHAPED_FIELD_PATTERN = /key|secret|token|password/i;

/** Marker substituted for any redacted value. */
export const REDACTED_VALUE = '[REDACTED]';

/**
 * Explicit denylist of `AppConfig` field names that must be redacted.
 *
 * Keep this in sync with `AppConfig`: the redaction test fails CI if a
 * secret-shaped field is missing here.
 */
export const CONFIG_REDACTED_FIELDS: ReadonlyArray<string> = [
  // Connection strings / credentials
  'databaseUrl',
  'redisUrl',

  // *Key fields
  'jwtKey',
  'jwtPublicKey',
  'encryptionKey',
  'signingKey',
  'apiKey',
  'sorobanContractKey',
  'webhookSigningKey',

  // *Secret fields
  'jwtSecret',
  'sessionSecret',
  'webhookSecret',
  'sorobanSecret',
  'stellarSecret',
  'oauthClientSecret',

  // *Token fields
  'apiToken',
  'githubToken',
  'slackToken',
  'webhookToken',
  'accessToken',
  'refreshToken',

  // Nested secrets bag
  'secrets.extra',
];

const REDACTED_FIELD_SET: ReadonlySet<string> = new Set(CONFIG_REDACTED_FIELDS);

/** Returns true if the given (possibly dotted) config path is denylisted. */
export function isRedactedConfigField(path: string): boolean {
  return REDACTED_FIELD_SET.has(path);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function redactValue(value: unknown, path: string): unknown {
  if (isRedactedConfigField(path)) {
    return REDACTED_VALUE;
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => redactValue(item, `${path}[${index}]`));
  }

  if (isPlainObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key;
      result[key] = redactValue(child, childPath);
    }
    return result;
  }

  return value;
}

/**
 * Returns a deep copy of `config` with every denylisted field replaced by
 * `REDACTED_VALUE`. The input object is never mutated.
 */
export function redactConfig(config: AppConfig): Record<string, unknown> {
  const redacted = redactValue(config, '');
  return redacted as Record<string, unknown>;
}