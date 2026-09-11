import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validKeepaliveUrl } from "../src/lib/keepalive-url.js";

test("keepalive download URLs accept both schemes without URL credentials or unsafe characters", () => {
	for (const url of ["http://example.test/body?size=1024", "https://example.test/body", "http://example.test:8080/body"]) assert.equal(validKeepaliveUrl(url), true, url);
	for (const url of ["ftp://example.test/body", "http://user:pass@example.test/body", "http://@example.test/body", "http://example.test/body#fragment", 'http://example.test/"header', "http://example.test/a b", "http://example.test/a\\b", "http://example.test:0/body", "http://example.test/\r\n", "http://例子.test/body", "https://example.test/" + "x".repeat(256)]) assert.equal(validKeepaliveUrl(url), false, url);
});

test("demo keepalive needs a CA only for HTTPS and saving never starts the schedule", async () => {
	const previousCwd = process.cwd();
	const previousMode = process.env.VITE_DEMO_MODE;
	let server;
	try {
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		process.env.VITE_DEMO_MODE = "1";
		const { createServer } = await import("vite");
		server = await createServer({ server: { middlewareMode: true }, appType: "custom", logLevel: "silent" });
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		assert.equal((await api.saveKeepalive(false, 175, 1, "http://example.test/body")).success, true);
		let state = await api.loadKeepalive();
		assert.equal(state.ready, true);
		assert.equal(state.enabled, false);
		assert.equal(state.jobDone, false);
		assert.equal((await api.provisionKeepaliveCa()).success, false);
		assert.equal((await api.loadKeepalive()).ready, true);
		assert.equal((await api.saveKeepalive(false, 175, 1, "https://example.test/body")).success, true);
		assert.equal((await api.loadKeepalive()).ready, false);
		assert.equal((await api.provisionKeepaliveCa()).success, true);
		assert.equal((await api.loadKeepalive()).ready, true);
		assert.equal((await api.saveKeepalive(false, 175, 1, "https://other.test/body")).success, true);
		state = await api.loadKeepalive();
		assert.equal(state.ready, false);
		assert.equal(state.enabled, false);
	} finally {
		try { await server?.close(); } finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});
