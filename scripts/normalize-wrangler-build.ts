import { dirname, join, relative, resolve } from "node:path";

const PROJECT_ROOT = resolve(import.meta.dir, "..");
const GENERATED_CONFIG = join(PROJECT_ROOT, "dist", "agent_action_gate", "wrangler.json");
const SOURCE_CONFIG = join(PROJECT_ROOT, "wrangler.jsonc");

/** Make Wrangler's generated source references portable, without changing bindings. */
export function normalizeWranglerBuildMetadata(value: unknown, sourceConfig: string, generatedConfig: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("generated Wrangler config must be an object");
  const config = value as Record<string, unknown>;
  if (config.configPath !== sourceConfig || config.userConfigPath !== sourceConfig) throw new Error("unexpected generated Wrangler source paths");
  const portableSource = relative(dirname(generatedConfig), sourceConfig).replaceAll("\\", "/");
  if (portableSource.startsWith("/") || portableSource === "") throw new Error("Wrangler source reference is not portable");
  return { ...config, configPath: portableSource, userConfigPath: portableSource };
}

if (import.meta.main) {
  const file = Bun.file(GENERATED_CONFIG);
  if (!(await file.exists())) throw new Error("generated Wrangler config is missing");
  const normalized = normalizeWranglerBuildMetadata(await file.json(), SOURCE_CONFIG, GENERATED_CONFIG);
  await Bun.write(GENERATED_CONFIG, `${JSON.stringify(normalized, null, 2)}\n`);
  process.stdout.write("Generated Wrangler source paths normalized.\n");
}
