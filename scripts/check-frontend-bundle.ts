import { readdir } from "node:fs/promises";
import { extname, join } from "node:path";

const OUTPUT_DIRECTORY = join(import.meta.dir, "..", "dist", "client");
const TEXT_EXTENSIONS = new Set(["", ".css", ".html", ".js", ".json", ".map", ".mjs", ".svg"]);
const FORBIDDEN_BINDING_NAMES = ["OPERATOR_API_KEY", "AAG_API_KEY", "GATE_API_KEY"];
const RAW_AGENT_KEY_PATTERN = /aag_(?:test|live|preview)_[A-Za-z0-9_-]{24,}/;

async function textFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await textFiles(path));
    else if (entry.isFile() && TEXT_EXTENSIONS.has(extname(entry.name))) files.push(path);
  }
  return files;
}

async function main(): Promise<void> {
  const files = await textFiles(OUTPUT_DIRECTORY);
  if (files.length === 0) throw new Error("frontend build output contains no text assets");

  const configuredSecrets = [
    process.env.OPERATOR_API_KEY,
    process.env.AAG_API_KEY,
    process.env.GATE_API_KEY,
  ].filter((value): value is string => typeof value === "string" && value.length >= 8);

  for (const file of files) {
    const contents = await Bun.file(file).text();
    for (const name of FORBIDDEN_BINDING_NAMES) {
      if (contents.includes(name)) throw new Error(`frontend asset contains server-only binding name: ${name}`);
    }
    for (const secret of configuredSecrets) {
      if (contents.includes(secret)) throw new Error("frontend asset contains a configured secret value");
    }
    if (RAW_AGENT_KEY_PATTERN.test(contents)) throw new Error("frontend asset contains a raw-looking Agent API key");
  }

  console.log(`Frontend secret scan passed (${files.length} assets).`);
}

await main();
