import { existsSync } from "node:fs";
import { join } from "node:path";

export type FindingKind = "personal_absolute_path" | "bearer_credential" | "raw_agent_key" | "token_literal" | "cloudflare_token" | "private_env_file" | "known_preview_secret";
export interface Finding { kind: FindingKind; file: string; line: number; }
const CREDENTIAL_NAMES = ["AAG_API_KEY", "GATE_API_KEY", "OPERATOR_API_KEY", "PREVIEW_API_KEY", "PREVIEW_OPERATOR_API_KEY", "GATE_PREVIEW_API_KEY", "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"];
const SKIP_DIR = /^(?:node_modules|\.git|\.wrangler|coverage)(?:\/|$)/;
const TEXT_LIMIT = 2_000_000;

/** Reports locations only. Never returns or prints matched credential text. */
export function scanText(file: string, content: string, knownSecrets: readonly string[] = []): Finding[] {
  const findings: Finding[] = [];
  const credentialAssignment = new RegExp(String.raw`(?:${CREDENTIAL_NAMES.join("|")})\s*[:=]\s*["']?([A-Za-z0-9_-]{16,})`, "i");
  const bearer = new RegExp("\\bBearer\\s+([A-Za-z0-9_\\-]{16,})\\b", "i");
  const rawAgentKey = new RegExp("\\baag_(?:test|live|preview)_[A-Za-z0-9_-]{24,}\\b", "i");
  const cfToken = new RegExp(String.raw`\b(?:cf|cloudflare)[_-]?(?:api[_-]?)?token\s*[:=]\s*["']?([A-Za-z0-9_-]{30,})`, "i");
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    const location = { file, line: index + 1 };
    if (/\/Users\/(?!<)[A-Za-z0-9._-]+\//.test(line)) findings.push({ ...location, kind: "personal_absolute_path" });
    if (bearer.test(line)) findings.push({ ...location, kind: "bearer_credential" });
    if (rawAgentKey.test(line)) findings.push({ ...location, kind: "raw_agent_key" });
    if (credentialAssignment.test(line)) findings.push({ ...location, kind: "token_literal" });
    if (cfToken.test(line)) findings.push({ ...location, kind: "cloudflare_token" });
    if (knownSecrets.some((secret) => secret.length >= 12 && line.includes(secret))) findings.push({ ...location, kind: "known_preview_secret" });
  }
  if (/(?:^|\/)\.(?:env(?:\..*)?|dev\.vars(?:\..*)?)$/.test(file) && !file.endsWith(".example")) findings.push({ kind: "private_env_file", file, line: 1 });
  return findings;
}

function git(args: string[]): { ok: boolean; text: string } {
  const child = Bun.spawnSync(["git", ...args], { stdout: "pipe", stderr: "ignore" });
  return { ok: child.exitCode === 0, text: new TextDecoder().decode(child.stdout) };
}

async function filesIn(root: string): Promise<string[]> {
  const candidate = git(["ls-files", "-co", "--exclude-standard", "-z"]);
  const names = candidate.ok ? candidate.text.split("\0").filter(Boolean) : [];
  // Built frontend assets are intentionally ignored by Git but must be checked.
  const scanBuilt = async (relative: string) => {
    const absolute = join(root, relative);
    if (!existsSync(absolute)) return;
    for await (const item of new Bun.Glob("**/*").scan({ cwd: absolute, onlyFiles: true })) names.push(`${relative}/${item}`);
  };
  await scanBuilt("dist");
  return [...new Set(names)].filter((name) => !SKIP_DIR.test(name));
}

export async function scanRepository(root: string): Promise<{ findings: Finding[]; historyChecked: boolean }> {
  const secrets = CREDENTIAL_NAMES.map((name) => Bun.env[name]).filter((item): item is string => typeof item === "string");
  const findings: Finding[] = [];
  for (const name of await filesIn(root)) {
    const file = Bun.file(join(root, name));
    if (!(await file.exists()) || file.size > TEXT_LIMIT) continue;
    const content = await file.text().catch(() => "");
    if (content.includes("\0")) continue;
    findings.push(...scanText(name, content, secrets));
  }
  const history = git(["log", "--all", "--format=commit:%H", "--no-ext-diff", "-p", "--", "."]);
  if (history.ok) {
    let commit = "history";
    let file = "unknown";
    for (const line of history.text.split("\n")) {
      if (line.startsWith("commit:")) commit = line.slice(7, 19);
      else if (line.startsWith("+++ b/")) file = line.slice(6);
      else if (line.startsWith("+") && !line.startsWith("+++")) {
        for (const found of scanText(`history:${commit}:${file}`, line.slice(1), secrets)) findings.push(found);
      }
    }
  }
  return { findings, historyChecked: history.ok };
}

if (import.meta.main) {
  const result = await scanRepository(process.cwd());
  for (const finding of result.findings) process.stdout.write(`FIND ${finding.kind} ${finding.file}:${finding.line}\n`);
  process.stdout.write(`Public release check: ${result.findings.length} finding(s); history ${result.historyChecked ? "checked" : "unavailable"}.\n`);
  if (result.findings.length > 0 || !result.historyChecked) process.exitCode = 1;
}
