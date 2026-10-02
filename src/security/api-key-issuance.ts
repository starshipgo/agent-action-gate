import { sha256Hex } from "./crypto";

const PUBLIC_PREFIX = "aag_test_";
const SECRET_BYTES = 32;
const DISPLAY_RANDOM_CHARS = 8;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export interface IssuedApiKeyMaterial {
  key_id: string;
  raw_api_key: string;
  key_hash: string;
  key_prefix: string;
}

/** Generates a credential once; callers must persist only hash and prefix. */
export async function issueApiKeyMaterial(
  randomBytes: Uint8Array = crypto.getRandomValues(new Uint8Array(SECRET_BYTES)),
  id: string = crypto.randomUUID(),
): Promise<IssuedApiKeyMaterial> {
  if (randomBytes.byteLength !== SECRET_BYTES || !/^[A-Za-z0-9-]{1,64}$/.test(id)) {
    throw new TypeError("invalid API key issuance input");
  }

  const randomPart = base64Url(randomBytes);
  const rawApiKey = `${PUBLIC_PREFIX}${randomPart}`;
  return {
    key_id: `aagk_${id}`,
    raw_api_key: rawApiKey,
    key_hash: await sha256Hex(rawApiKey),
    key_prefix: `${PUBLIC_PREFIX}${randomPart.slice(0, DISPLAY_RANDOM_CHARS)}`,
  };
}
