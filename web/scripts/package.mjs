import { gzipSync } from "node:zlib";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const html = await readFile(new URL("../build/index.html", import.meta.url));
const source = html.toString();
if (/<script\s+[^>]*src=|<link\s+[^>]*rel=["']stylesheet["'][^>]*href=/.test(source)) {
	throw new Error("The production page is not fully inline");
}

const bundle = gzipSync(html, { level: 9 });
if (bundle.length > 256 * 1024) throw new Error(`Bundle is too large: ${bundle.length} bytes`);

const output = new URL("../../code/data/", import.meta.url);
await mkdir(output, { recursive: true });
await writeFile(new URL("index.html.gz", output), bundle);
const rows = [];
for (let offset = 0; offset < bundle.length; offset += 16) {
	rows.push(`\t${[...bundle.subarray(offset, offset + 16)].map((byte) => `0x${byte.toString(16).padStart(2, "0")}`).join(", ")},`);
}
await writeFile(
	new URL("../../code/web_bundle.h", import.meta.url),
	`#pragma once\n#include <Arduino.h>\n\nstatic const uint8_t WEB_BUNDLE[] PROGMEM = {\n${rows.join("\n")}\n};\nstatic const size_t WEB_BUNDLE_SIZE = sizeof(WEB_BUNDLE);\n`,
);
console.log(`Web bundle: ${html.length} bytes raw, ${bundle.length} bytes gzip`);
