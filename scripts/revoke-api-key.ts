/**
 * Revoke one API key by its non-secret database id. This script intentionally
 * does not accept a raw API key, so credentials cannot leak into shell history
 * or Wrangler arguments.
 *
 * Run this yourself from the repository root, choosing exactly one target:
 *
 *   bun run scripts/revoke-api-key.ts --local --key-id <api-key-id>
 *
 * Use `--preview` or `--remote` only after Step 5D resources, the matching
 * Wrangler binding, and authentication have been configured by the operator.
 * Script-level `--preview` safely expands to Wrangler `--remote --preview`.
 */

interface RevokeOptions {
  target: "--local" | "--remote" | "--preview";
  database: string;
  keyId: string;
}

function fail(message: string): never {
  console.error(`ERROR: ${message}`);
  console.error(
    "Usage: bun run scripts/revoke-api-key.ts (--local|--preview|--remote) " +
      "--key-id <id> [--database <name>]",
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

function parseOptions(args: readonly string[]): RevokeOptions {
  let target: RevokeOptions["target"] | undefined;
  let database = "DB";
  let keyId: string | undefined;

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
      case "--key-id":
        keyId = requiredValue(args, index, flag);
        index += 1;
        break;
      default:
        fail(`unknown argument: ${flag ?? "<missing>"}`);
    }
  }

  if (target === undefined) {
    fail("choose exactly one of --local, --preview, or --remote");
  }
  if (keyId === undefined) fail("--key-id is required");

  return {
    target,
    database: validateText("--database", database, 128),
    keyId: validateText("--key-id", keyId, 128),
  };
}

function sqlText(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function wranglerTargetArgs(
  target: RevokeOptions["target"],
): readonly string[] {
  return target === "--preview" ? ["--remote", "--preview"] : [target];
}

async function main(): Promise<void> {
  const options = parseOptions(Bun.argv.slice(2));
  const wranglerPath = `${import.meta.dir}/../node_modules/.bin/wrangler`;
  if (!(await Bun.file(wranglerPath).exists())) {
    throw new Error("local Wrangler executable is missing; run bun install first");
  }

  const sql = [
    "UPDATE api_keys",
    "SET status = 'revoked', revoked_at = unixepoch()",
    `WHERE id = ${sqlText(options.keyId)} AND status = 'active'`,
    "RETURNING id, key_prefix, tenant_id, status, revoked_at;",
  ].join(" ");

  const child = Bun.spawn(
    [
      wranglerPath,
      "d1",
      "execute",
      options.database,
      ...wranglerTargetArgs(options.target),
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
    throw new Error(`Wrangler D1 revocation failed: ${stderr.trim() || `exit ${exitCode}`}`);
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
    throw new Error("No active API key matched that key id; nothing was revoked");
  }

  console.log("API key revoked.");
}

if (import.meta.main) {
  await main();
}

export {};
