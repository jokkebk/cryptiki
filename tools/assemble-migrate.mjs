import { writeFileSync } from "node:fs";
import { buildMigrate } from "./build.mjs";
import { syncCspHashes } from "./csp.mjs";

const html = buildMigrate();
writeFileSync(new URL("../public/migrate.html", import.meta.url), syncCspHashes("migrate.html", html));
