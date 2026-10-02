/**
 * Create and store one API-key record using Wrangler's D1 CLI.
 *
 * This script deliberately sends only the SHA-256 hash, display prefix, and
 * non-secret metadata to D1. The full credential is printed once, only after
 * Wrangler confirms that the insert succeeded. It is never placed in an
 * argument passed to Wrangler or written to a file.
 *
 * Run this yourself from the repository root. Choose exactly one execution
 * target; remote operation is never the default:
 *
 *   bun run scripts/create-api-key.ts --local \
 *     --principal-id <stable-principal-id> --tenant-id <tenant-id> \
 *     --label <operator-label> --daily-ai-limit <non-negative-integer>
 *
 * Add `--database <binding-or-database-name>` when `DB` is not appropriate.
 * Use `--preview` or `--remote` only after the Step 5D resources, matching
 * Wrangler binding, and authentication have been configured by the operator.
 * Script-level `--preview` safely expands to Wrangler `--remote --preview`.
 */

import { issueApiKeyMaterial } from "../src/security/api-key-issuance";

interface CreateOptions {
  target: "--local" | "--remote" | "--preview";
  database: string;
  principalId: string;
  tenantId: string;
  label: string;
  dailyAiLimit: number;
}

function fail(message: string): never {
  console.error(`ERROR: ${message}`);
  console.error(
    "Usage: bun run scripts/create-api-key.ts (--local|--preview|--remote) " +
      "--principal-id <id> --tenant-id <id> --label <label> " +
      "--daily-ai-limit <integer> [--database <name>]",
  );
  process.exit(2);
}

function requiredValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) {
    fail(`${flag} requires a value`);
  }
  return value;
}

function validateText(name: string, value: string, maxLength: number): string {
  if (value.trim() !== value || value.length === 0 || value.length > maxLength) {
    fail(`${name} must be non-empty, unpadded text of at most ${maxLength} characters`);
  }
  if (/\p{Cc}/u.test(value)) {
    fail(`${name} must not contain control characters`);
  }
  return value;
}

function validateTenant(value: string): string {
  const tenantId = validateText("--tenant-id", value, 128);
  if (tenantId !== tenantId.toLowerCase() || !/^[a-z0-9._-]+$/.test(tenantId)) {
    fail("--tenant-id must use canonical lowercase letters, digits, dot, underscore, or hyphen");
  }
  return tenantId;
}

function parseOptions(args: readonly string[]): CreateOptions {
  let target: CreateOptions["target"] | undefined;
  let database = "DB";
  let principalId: string | undefined;
  let tenantId: string | undefined;
  let label: string | undefined;
  let dailyAiLimit: number | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    switch (flag) {
      case "--local":
      case "--preview":
      case "--remote":
        if (target !== undefined) {
          fail("choose exactly one of --local, --preview, or --remote");
        }
        target = flag;
        break;
      case "--database":
        database = requiredValue(args, index, flag);
        index += 1;
        break;
      case "--principal-id":
        principalId = requiredValue(args, index, flag);
        index += 1;
        break;
      case "--tenant-id":
        tenantId = requiredValue(args, index, flag);
        index += 1;
        break;
      case "--label":
        label = requiredValue(args, index, flag);
        index += 1;
        break;
      case "--daily-ai-limit": {
        const rawLimit = requiredValue(args, index, flag);
        if (!/^(0|[1-9][0-9]*)$/.test(rawLimit)) {
          fail("--daily-ai-limit must be a non-negative integer");
        }
        dailyAiLimit = Number(rawLimit);
        if (!Number.isSafeInteger(dailyAiLimit)) {
          fail("--daily-ai-limit exceeds the JavaScript safe-integer range");
        }
        index += 1;
        break;
      }
      default:
        fail(`unknown argument: ${flag ?? "<missing>"}`);
    }
  }

  if (target === undefined) {
    fail("choose exactly one of --local, --preview, or --remote");
  }
  if (principalId === undefined) fail("--principal-id is required");
  if (tenantId === undefined) fail("--tenant-id is required");
  if (label === undefined) fail("--label is required");
  if (dailyAiLimit === undefined) fail("--daily-ai-limit is required");

  return {
    target,
    database: validateText("--database", database, 128),
    principalId: validateText("--principal-id", principalId, 128),
    tenantId: validateTenant(tenantId),
    label: validateText("--label", label, 200),
    dailyAiLimit,
  };
}

function sqlText(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function wranglerTargetArgs(
  target: CreateOptions["target"],
): readonly string[] {
  return target === "--preview" ? ["--remote", "--preview"] : [target];
}

async function executeD1(
  database: string,
  target: CreateOptions["target"],
  sql: string,
): Promise<void> {
  const wranglerPath = `${import.meta.dir}/../node_modules/.bin/wrangler`;
  if (!(await Bun.file(wranglerPath).exists())) {
    throw new Error("local Wrangler executable is missing; run bun install first");
  }

  const child = Bun.spawn(
    [
      wranglerPath,
      "d1",
      "execute",
      database,
      ...wranglerTargetArgs(target),
      "--command",
      sql,
      "--json",
    ],
    {
      cwd: `${import.meta.dir}/..`,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  if (exitCode !== 0) {
    throw new Error(`Wrangler D1 insert failed: ${stderr.trim() || `exit ${exitCode}`}`);
  }

  const output = JSON.parse(stdout) as unknown;
  const rows = Array.isArray(output)
    ? output.flatMap((entry) =>
        entry !== null &&
        typeof entry === "object" &&
        "results" in entry &&
        Array.isArray(entry.results)
          ? entry.results
          : [],
      )
    : [];
  if (rows.length !== 1) {
    throw new Error("Wrangler D1 insert did not confirm exactly one stored key");
  }
}

async function main(): Promise<void> {
  const options = parseOptions(Bun.argv.slice(2));
  const issued = await issueApiKeyMaterial();
  const rawKey = issued.raw_api_key;
  const keyHash = issued.key_hash;
  const keyPrefix = issued.key_prefix;
  const keyId = issued.key_id;

  const sql = [
    "INSERT INTO api_keys",
    "(id, principal_id, key_hash, key_prefix, tenant_id, label, status, daily_ai_limit)",
    `VALUES (${sqlText(keyId)}, ${sqlText(options.principalId)}, ${sqlText(keyHash)},`,
    `${sqlText(keyPrefix)}, ${sqlText(options.tenantId)}, ${sqlText(options.label)},`,
    `'active', ${options.dailyAiLimit})`,
    "RETURNING id, key_prefix, tenant_id, status;",
  ].join(" ");

  await executeD1(options.database, options.target, sql);

  console.log(`Stored API-key metadata under key id: ${keyId}`);
  console.log(`API key (copy now; it will not be shown again): ${rawKey}`);
}

if (import.meta.main) {
  await main();
}

export { sha256Hex } from "../src/security/crypto";
