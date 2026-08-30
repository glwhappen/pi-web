import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const PI_WEB_AUTH_USERNAME = "pi";
export const WEB_AUTH_COOKIE = "pi-web-auth";
export const WEB_SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;

function hashSecret(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Derive the session signing key from the configured password so the cookie
 * stays verifiable across Next.js runtimes (the middleware and route handlers
 * keep separate module instances). A cookie holder knows the password anyway,
 * so this grants no extra information.
 */
function sessionSigningKey(password: string): Buffer {
  return hashSecret(`pi-web-session:v1:${password}`);
}

function secretsEqual(actual: string, expected: string): boolean {
  return timingSafeEqual(hashSecret(actual), hashSecret(expected));
}

export function isWebPasswordEnabled(
  password: string | undefined = process.env.PI_WEB_PASSWORD,
): password is string {
  return typeof password === "string" && password.length > 0;
}

export function isValidBasicAuthorization(
  authorization: string | null,
  password = process.env.PI_WEB_PASSWORD,
): boolean {
  if (!isWebPasswordEnabled(password) || !authorization) return false;

  const match = /^Basic\s+(\S+)$/i.exec(authorization);
  if (!match) return false;

  let credentials: string;
  try {
    const decoded = Buffer.from(match[1], "base64");
    if (decoded.toString("base64") !== match[1]) return false;
    credentials = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
  } catch {
    return false;
  }

  const separator = credentials.indexOf(":");
  if (separator === -1) return false;

  const username = credentials.slice(0, separator);
  const suppliedPassword = credentials.slice(separator + 1);
  const usernameMatches = secretsEqual(username, PI_WEB_AUTH_USERNAME);
  const passwordMatches = secretsEqual(suppliedPassword, password);
  return usernameMatches && passwordMatches;
}

function base64UrlDecode(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.toString("base64url") !== value) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Issue the value for the `pi-web-auth` session cookie: a base64url JSON
 * payload (`{exp}`) plus an HMAC-SHA256 signature, separated by a dot.
 */
export function createWebSessionCookieValue(expiresAt: number, password: string): string {
  const payload = Buffer.from(JSON.stringify({ exp: expiresAt }), "utf8");
  const signature = createHmac("sha256", sessionSigningKey(password)).update(payload).digest();
  return `${payload.toString("base64url")}.${signature.toString("base64url")}`;
}

export function issueWebSessionCookieValue(
  password: string | undefined = process.env.PI_WEB_PASSWORD,
): string {
  if (!isWebPasswordEnabled(password)) {
    throw new Error("Cannot issue a web session without a configured password");
  }
  return createWebSessionCookieValue(Date.now() + WEB_SESSION_MAX_AGE_SECONDS * 1000, password);
}

export function isValidWebSessionCookieValue(
  value: string | null,
  password: string | undefined = process.env.PI_WEB_PASSWORD,
): boolean {
  if (!value || !isWebPasswordEnabled(password)) return false;
  const separator = value.indexOf(".");
  if (separator === -1 || value.indexOf(".", separator + 1) !== -1) return false;

  const payload = base64UrlDecode(value.slice(0, separator));
  const provided = base64UrlDecode(value.slice(separator + 1));
  if (!payload || !provided) return false;

  const expected = createHmac("sha256", sessionSigningKey(password)).update(payload).digest();
  if (!timingSafeEqual(provided, expected)) return false;

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    return false;
  }
  return typeof parsed === "object" && parsed !== null
    && typeof (parsed as { exp?: unknown }).exp === "number"
    && (parsed as { exp: number }).exp > Date.now();
}

export function getWebSessionCookieValue(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const name = part.slice(0, part.indexOf("=")).trim();
    if (name === WEB_AUTH_COOKIE) return part.slice(part.indexOf("=") + 1).trim();
  }
  return null;
}

export function isWebAuthenticated(request: Request, password: string | undefined): boolean {
  if (!isWebPasswordEnabled(password)) return true;
  return isValidBasicAuthorization(request.headers.get("authorization"), password)
    || isValidWebSessionCookieValue(getWebSessionCookieValue(request), password);
}

/** Verify a password supplied as a plain string (e.g. the login form). */
export function verifyWebPassword(supplied: string, password: string | undefined): boolean {
  if (!isWebPasswordEnabled(password) || !supplied) return false;
  const authorization = `Basic ${Buffer.from(
    `${PI_WEB_AUTH_USERNAME}:${supplied}`,
    "utf8",
  ).toString("base64")}`;
  return isValidBasicAuthorization(authorization, password);
}
