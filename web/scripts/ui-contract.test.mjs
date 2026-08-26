import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import process from "node:process";
import test from "node:test";

async function loadUiContract() {
	try {
		return await import("../src/lib/esim-ui.js");
	} catch (error) {
		assert.fail(`eSIM UI behavior helper is missing: ${error instanceof Error ? error.message : String(error)}`);
	}
}

test("terminal eSIM jobs fetch fresh profiles before reporting completion", async () => {
	const { refreshEsimAfterTerminal } = await loadUiContract();
	let calls = 0;
	const fresh = await refreshEsimAfterTerminal(async () => {
		calls += 1;
		return { profiles: [{ handle: "fresh" }], job: { state: "succeeded" } };
	}, { profiles: [{ handle: "stale" }], job: { state: "succeeded" } });
	assert.equal(calls, 1);
	assert.deepEqual(fresh.profiles, [{ handle: "fresh" }]);
});

test("closing the eSIM delete dialog clears context and returns its originating focus", async () => {
	const { closeEsimDeleteDialog } = await loadUiContract();
	assert.deepEqual(closeEsimDeleteDialog({ handle: "opaque", originId: "delete-1" }), {
		handle: "", originId: "", focusId: "delete-1"
	});
});

test("demo eSIM switch makes the selected profile enabled", async () => {
	const previousMode = process.env.VITE_DEMO_MODE;
	const previousCwd = process.cwd();
	let server;
	try {
		process.env.VITE_DEMO_MODE = "1";
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({ server: { middlewareMode: true }, appType: "custom", logLevel: "silent" });
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		const before = await api.loadEsim();
		const target = before.profiles.find((profile) => profile.state === "disabled");
		assert.ok(target);
		assert.equal((await api.postEsimAction("switch", target.handle)).success, true);
		const after = await api.loadEsim();
		assert.equal(after.profiles.find((profile) => profile.handle === target.handle)?.state, "enabled");
		assert.ok(after.profiles.filter((profile) => profile.handle !== target.handle).every((profile) => profile.state === "disabled"));
	} finally {
		try { await server?.close(); }
		finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});
