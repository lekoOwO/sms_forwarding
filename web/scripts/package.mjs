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
console.log(`Web bundle: ${html.length} bytes raw, ${bundle.length} bytes gzip`);
