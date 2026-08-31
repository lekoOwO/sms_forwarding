import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const WEB_ROOT = resolve(new URL("..", import.meta.url).pathname);
const VITE_BIN = join(WEB_ROOT, "node_modules", "vite", "bin", "vite.js");

function makeFixture(page, routes = {}) {
	const root = mkdtempSync(join(tmpdir(), "sms-vite-hash-"));
	const routeRoot = join(root, "src", "routes");
	mkdirSync(routeRoot, { recursive: true });
	cpSync(join(WEB_ROOT, "vite.config.ts"), join(root, "vite.config.ts"));
	cpSync(join(WEB_ROOT, "src", "app.html"), join(root, "src", "app.html"));
	symlinkSync(join(WEB_ROOT, "node_modules"), join(root, "node_modules"), "dir");
	writeFileSync(join(root, "package.json"), '{"type":"module"}\n');
	writeFileSync(join(routeRoot, "+layout.js"), "export const prerender = true;\n");
	writeFileSync(join(routeRoot, "+page.svelte"), page);
	for (const [route, source] of Object.entries(routes)) {
		const directory = join(routeRoot, route);
		mkdirSync(directory, { recursive: true });
		writeFileSync(join(directory, "+page.svelte"), source);
	}
	return root;
}

function build(root) {
	try {
		const output = execFileSync(process.execPath, [VITE_BIN, "build"], {
			cwd: root,
			env: { ...process.env, CI: "1" },
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			timeout: 30_000
		});
		return { status: 0, output };
	} catch (error) {
		const output = [error.stdout, error.stderr]
			.map((part) => part?.toString() ?? "")
			.join("\n");
		return { status: error.status ?? 1, output };
	}
}

test("production builds enforce the narrow client hash whitelist", () => {
	const cases = [
		{
			name: "known hash on home",
			page: '<a href="/#overview">Known route</a>',
			passes: true
		},
		{
			name: "unknown hash on home",
			page: '<a href="/#not-a-route">Unknown route</a>',
			passes: false,
			errorText: "not-a-route"
		},
		{
			name: "missing imported asset",
			page: '<script>import missingAsset from "$lib/missing.svg";</script><img src={missingAsset} alt="Missing asset" />',
			passes: false,
			errorText: "missing.svg"
		},
		{
			name: "known hash on non-home path",
			page: '<a href="/other#overview">Other route</a>',
			routes: { other: "<h1>Other page</h1>" },
			passes: false,
			errorText: "other"
		}
	];

	for (const fixture of cases) {
		const root = makeFixture(fixture.page, fixture.routes);
		try {
			const result = build(root);
			assert.equal(result.status === 0, fixture.passes, `${fixture.name} build status\n${result.output}`);
			if (fixture.errorText) assert.match(result.output, new RegExp(fixture.errorText));
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	}
});
