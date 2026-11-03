// One-time helper: creates the RATE_LIMIT KV namespace and enables the binding in wrangler.toml.
// Usage: npm run setup:kv   (requires `npx wrangler login` first). Then redeploy.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const FILE = 'wrangler.toml';
const toml = readFileSync(FILE, 'utf8');
if (/^\[\[kv_namespaces\]\]/m.test(toml)) {
  console.log('wrangler.toml already has an active [[kv_namespaces]] block. Nothing to do.');
  process.exit(0);
}

let out;
try {
  out = execFileSync('npx', ['wrangler', 'kv', 'namespace', 'create', 'RATE_LIMIT'], { encoding: 'utf8', stdio: ['inherit', 'pipe', 'inherit'] });
} catch {
  console.error('\nCould not create the namespace. If it already exists, find its id with `npx wrangler kv namespace list`\nand uncomment the [[kv_namespaces]] block in wrangler.toml by hand.');
  process.exit(1);
}

const id = out.match(/\bid\b"?\s*[=:]\s*"([0-9a-f]{32})"/i)?.[1];
const placeholder = /# \[\[kv_namespaces\]\]\n# binding = "RATE_LIMIT"\n# id = "<your-kv-namespace-id>"/;
if (!id || !placeholder.test(toml)) {
  console.log(out);
  console.error('\nCreated the namespace, but could not patch wrangler.toml automatically. Uncomment the [[kv_namespaces]] block and paste the id above.');
  process.exit(1);
}

writeFileSync(FILE, toml.replace(placeholder, `[[kv_namespaces]]\nbinding = "RATE_LIMIT"\nid = "${id}"`));
console.log(`\nDone: RATE_LIMIT bound to KV namespace ${id}. Commit wrangler.toml and redeploy.`);
