const encoder = new TextEncoder();

export const OPERATOR_SESSION_COOKIE = "__Host-aag_operator_session";
export const OPERATOR_SESSION_TTL_SECONDS = 8 * 60 * 60;

const SESSION_VERSION = "v1";
const NONCE_BYTES = 18;
const SESSION_PATTERN = /^v1\.(\d{1,12})\.([A-Za-z0-9_-]{24})\.([A-Za-z0-9_-]{43})$/;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(`agent-action-gate:operator-session:v1\0${secret}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signature(secret: string, payload: string): Promise<string> {
  const digest = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret),
    encoder.encode(payload),
  );
  return base64Url(new Uint8Array(digest));
}

function sessionPayload(expiresAt: number, nonce: string): string {
  return `${SESSION_VERSION}.${expiresAt}.${nonce}`;
}

function cookieValue(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (header === null) return null;

  const matches = header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${OPERATOR_SESSION_COOKIE}=`));
  if (matches.length !== 1) return null;

  return matches[0]!.slice(OPERATOR_SESSION_COOKIE.length + 1);
}

export interface IssuedOperatorSession {
  cookie: string;
  expires_at: number;
}

export async function issueOperatorSession(
  secret: string,
  nowUnixSeconds: number,
  randomBytes: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE_BYTES)),
): Promise<IssuedOperatorSession> {
  if (secret.length < 16) {
    throw new TypeError("operator session secret is unavailable");
  }
  if (
    !Number.isSafeInteger(nowUnixSeconds) ||
    nowUnixSeconds < 0 ||
    randomBytes.byteLength !== NONCE_BYTES
  ) {
    throw new TypeError("invalid operator session input");
  }

  const expiresAt = nowUnixSeconds + OPERATOR_SESSION_TTL_SECONDS;
  const nonce = base64Url(randomBytes);
  const payload = sessionPayload(expiresAt, nonce);
  const value = `${payload}.${await signature(secret, payload)}`;

  return {
    cookie: [
      `${OPERATOR_SESSION_COOKIE}=${value}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      `Max-Age=${OPERATOR_SESSION_TTL_SECONDS}`,
      `Expires=${new Date(expiresAt * 1_000).toUTCString()}`,
    ].join("; "),
    expires_at: expiresAt,
  };
}

export async function authenticateOperatorSession(
  request: Request,
  configuredSecret: string | undefined,
  nowUnixSeconds: number,
): Promise<boolean> {
  if (
    configuredSecret === undefined ||
    configuredSecret.length < 16 ||
    !Number.isSafeInteger(nowUnixSeconds) ||
    nowUnixSeconds < 0
  ) {
    return false;
  }

  const value = cookieValue(request);
  const match = value === null ? null : SESSION_PATTERN.exec(value);
  if (match === null) return false;

  const expiresAt = Number(match[1]);
  const nonce = match[2]!;
  const suppliedSignature = match[3]!;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= nowUnixSeconds) {
    return false;
  }

  const payload = sessionPayload(expiresAt, nonce);
  const expectedSignature = await signature(configuredSecret, payload);
  if (expectedSignature.length !== suppliedSignature.length) return false;

  let difference = 0;
  for (let index = 0; index < expectedSignature.length; index += 1) {
    difference |=
      expectedSignature.charCodeAt(index) ^ suppliedSignature.charCodeAt(index);
  }
  return difference === 0;
}

export function clearOperatorSessionCookie(): string {
  return [
    `${OPERATOR_SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ].join("; ");
}
