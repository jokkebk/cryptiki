import { readFileSync } from "node:fs";
import { builders } from "./build.mjs";
import { embedCsp } from "./csp.mjs";

const script = { "index.html": "npm run assemble", "migrate.html": "npm run assemble:migrate" };
for (const [name, build] of Object.entries(builders)) {
  const committed = readFileSync(new URL(`../public/${name}`, import.meta.url), "utf8");
  if (embedCsp(name, build()) !== committed) throw Error(`public/${name} is stale: templates or src/ changed after it was assembled. Run ${script[name]}`);
  console.log(`public/${name} matches its template and sources`);
}
