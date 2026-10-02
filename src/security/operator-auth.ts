import { sha256Hex } from "./crypto";

export type OperatorAuthenticationResult =
  | { ok: true }
  | { ok: false; reason: "unauthorized" | "unavailable" };

export function extractOperatorBearerCredential(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  const match =
    authorization === null ? null : /^Bearer ([^\s]+)$/i.exec(authorization);
  return match?.[1] ?? null;
}

function equalHex(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

/** Operator authority is checked only against its dedicated secret binding. */
export async function authenticateOperatorCredential(
  supplied: string | null,
  configuredSecret: string | undefined,
): Promise<OperatorAuthenticationResult> {
  if (configuredSecret === undefined || configuredSecret.length < 16) {
    return { ok: false, reason: "unavailable" };
  }

  if (supplied === null) {
    return { ok: false, reason: "unauthorized" };
  }

  try {
    const [suppliedHash, configuredHash] = await Promise.all([
      sha256Hex(supplied),
      sha256Hex(configuredSecret),
    ]);

    return equalHex(suppliedHash, configuredHash)
      ? { ok: true }
      : { ok: false, reason: "unauthorized" };
  } catch {
    return { ok: false, reason: "unavailable" };
  }
}

/** Operator authority is checked only against its dedicated secret binding. */
export async function authenticateOperator(
  request: Request,
  configuredSecret: string | undefined,
): Promise<OperatorAuthenticationResult> {
  return authenticateOperatorCredential(
    extractOperatorBearerCredential(request),
    configuredSecret,
  );
}
