import { writeFileSync } from "node:fs";
import { buildIndex } from "./build.mjs";
import { syncCspHashes } from "./csp.mjs";

const html = buildIndex();
writeFileSync(new URL("../public/index.html", import.meta.url), html);
syncCspHashes("index.html", html);
