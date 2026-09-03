import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { gunzipSync } from "node:zlib";

test("package output is deterministic and ESP-IDF compatible", async () => {
	const root = mkdtempSync(join(tmpdir(), "web-assets-"));
	const scripts = join(root, "web", "scripts");
	const build = join(root, "web", "build");
	const code = join(root, "code");
	mkdirSync(scripts, { recursive: true });
	mkdirSync(build, { recursive: true });
	mkdirSync(code, { recursive: true });
	writeFileSync(join(scripts, "package.mjs"), readFileSync(new URL("./package.mjs", import.meta.url)));
	writeFileSync(join(build, "index.html"), "<!doctype html><html><body>inline app</body></html>");
	writeFileSync(join(build, "provisioning.html"), "<!doctype html><html><body>provisioning</body></html>");

	const script = pathToFileURL(join(scripts, "package.mjs")).href;
	await import(`${script}?run=1`);
	const header = readFileSync(join(root, "code", "web_assets.h"), "utf8");
	const first = readFileSync(join(root, "code", "web_assets.cpp"), "utf8");
	await import(`${script}?run=2`);
	const second = readFileSync(join(root, "code", "web_assets.cpp"), "utf8");

	assert.equal(second, first);
	assert.match(header, /struct WebAsset/);
	assert.match(first, /findWebPanelAsset/);
	assert.doesNotMatch(header + first, /Arduino\.h|PROGMEM/);
	const bytes = first.match(/WEB_INDEX_DATA\[\] = \{([\s\S]*?)\};/)[1]
		.match(/0x[0-9a-f]{2}/g).map((value) => Number(value));
	assert.equal(gunzipSync(Buffer.from(bytes)).toString(), "<!doctype html><html><body>inline app</body></html>");
});

test("CI owns the Svelte asset pipeline", () => {
	const workflow = readFileSync(new URL("../../.github/workflows/build.yml", import.meta.url), "utf8");
	assert.match(workflow, /node-version: '24\.14\.0'/);
	assert.match(workflow, /npm ci --prefix web/);
	assert.match(workflow, /npm --prefix web run check/);
	assert.match(workflow, /npm --prefix web run build/);
	assert.doesNotMatch(workflow, /build_web_assets\.py|code\/web_src/);
	assert.equal(existsSync(new URL("../../tools/build_web_assets.py", import.meta.url)), false);
	assert.equal(existsSync(new URL("../../code/web_src", import.meta.url)), false);
});

test("all locales show the runtime provisioning SSID", () => {
	for (const locale of ["zh-TW", "zh-CN", "en"]) {
		const messages = JSON.parse(readFileSync(new URL(`../src/lib/locales/${locale}.json`, import.meta.url), "utf8"));
		assert.match(messages.apModeDescription, /SMS-Forwarder-XXXXXX/);
		assert.doesNotMatch(messages.apModeDescription, /sms-forwarder-<MAC6>/);
	}
});

test("a channel CA result renders its code and detail in its own live region", async () => {
	const previousCwd = process.cwd();
	let server;
	try {
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({ server: { middlewareMode: true }, appType: "custom", logLevel: "silent" });
		const [{ render }, component] = await Promise.all([
			server.ssrLoadModule("svelte/server"),
			server.ssrLoadModule("/src/lib/components/CellularCaResult.svelte")
		]);
		const { body } = render(component.default, { props: {
			status: { configured: false, sha256: "" },
			saveResult: { state: "error", code: "ACTION_CONFIG_INVALID", data: {}, detail: "push1cellularUrl" },
			result: { state: "error", code: "PUSH_CA_REJECTED", data: {}, detail: "candidate rejected" },
			title: "Root CA status", saveTitle: "Save result", ready: "Ready", notReady: "Not ready", locale: "en"
		} });
		assert.match(body, /Not ready/);
		assert.match(body, /configuration is invalid/i);
		assert.match(body, /push1cellularUrl/);
		assert.match(body, /device rejected all matching root CA candidates/i);
		assert.match(body, /candidate rejected/);
		assert.match(body, /aria-live="polite"/);
	} finally {
		try { await server?.close(); } finally { process.chdir(previousCwd); }
	}
});

test("demo API rejects invalid forwarding regex and tests only configured push channels", async () => {
	const previousMode = process.env.VITE_DEMO_MODE;
	const previousCwd = process.cwd();
	let server;
	try {
		process.env.VITE_DEMO_MODE = "1";
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({
			server: { middlewareMode: true },
			appType: "custom",
			logLevel: "silent"
		});
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		const before = await api.loadSnapshot();
		const rejected = await api.postForm("/save", {
			deviceName: "must-not-save",
			forwardRules: "re\t(?=a)\temail"
		});
		assert.deepEqual([rejected.success, rejected.code, rejected.detail],
			[false, "ACTION_CONFIG_INVALID", "forwardRules"]);
		assert.deepEqual((await api.loadSnapshot()).config, before.config);
		assert.equal(typeof api.runPushTest, "function");
		const sent = await api.runPushTest?.(0);
		await api.postForm("/save", {
			push1en: true, push1type: 9, push1name: "Incomplete",
			push1url: "https://push.example/message"
		});
		const incomplete = await api.runPushTest?.(1);
		assert.deepEqual([sent.done, sent.success, incomplete.done, incomplete.success],
			[true, true, true, false]);
	} finally {
		try { await server?.close(); }
		finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});

test("real push test helper accepts 409 status bodies, polls, and aborts stalled requests", async () => {
	const previousMode = process.env.VITE_DEMO_MODE;
	const previousCwd = process.cwd();
	const previousFetch = globalThis.fetch;
	let server;
	try {
		delete process.env.VITE_DEMO_MODE;
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({
			server: { middlewareMode: true }, appType: "custom", logLevel: "silent"
		});
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		const calls = [];
		globalThis.fetch = async (path, init = {}) => {
			calls.push([path, init]);
			if (path === "/api/config") return new Response(JSON.stringify({ csrfToken: "real-csrf" }), {
				status: 200, headers: { "Content-Type": "application/json" }
			});
			const status = calls.filter(([value]) => String(value).startsWith("/api/push/test")).length === 1
				? { queued: true, running: false, done: false, success: false, message: "Already queued" }
				: { queued: false, running: false, done: true, success: true, message: "Sent" };
			return new Response(JSON.stringify(status), {
				status: status.queued ? 409 : 200, headers: { "Content-Type": "application/json" }
			});
		};
		await api.loadSnapshot();
		const completed = await api.runPushTest(0, undefined, 2000);
		assert.deepEqual([completed.done, completed.success], [true, true]);
		const pushCalls = calls.filter(([path]) => String(path).startsWith("/api/push/test"));
		assert.deepEqual(pushCalls.map(([, init]) => init.method ?? "GET"), ["POST", "GET"]);
		assert.equal(pushCalls[0][1].body, undefined);
		assert.equal(pushCalls[0][1].headers["X-CSRF-Token"], "real-csrf");

		globalThis.fetch = (_path, init = {}) => new Promise((_resolve, reject) => {
			init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
		});
		const outcome = await Promise.race([
			api.runPushTest(0, undefined, 20).then(() => "resolved", (error) => error.message),
			new Promise((resolve) => setTimeout(() => resolve("hung"), 150))
		]);
		assert.match(outcome, /timed out/i);
	} finally {
		globalThis.fetch = previousFetch;
		try { await server?.close(); }
		finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});

test("push test validator keeps cleanup reasons disjoint from primary reasons", async () => {
	const previousMode = process.env.VITE_DEMO_MODE;
	const previousCwd = process.cwd();
	const previousFetch = globalThis.fetch;
	let server;
	try {
		delete process.env.VITE_DEMO_MODE;
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({
			server: { middlewareMode: true }, appType: "custom", logLevel: "silent"
		});
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		const validPrimary = {
			queued: false, running: false, done: true, success: false,
			message: "bounded failure", failureReason: "terminal_failure"
		};
		globalThis.fetch = async (path) => {
			if (path === "/api/config") return new Response(JSON.stringify({ csrfToken: "csrf" }), {
				status: 200, headers: { "Content-Type": "application/json" }
			});
			return new Response(JSON.stringify(validPrimary), {
				status: 200, headers: { "Content-Type": "application/json" }
			});
		};
		await api.loadSnapshot();
		const accepted = await api.runPushTest(0, undefined, 1000);
		assert.equal(accepted.failureReason, "terminal_failure");

		const responseInvalid = {
			queued: false, running: false, done: true, success: false,
		message: "malformed modem response", failureReason: "response_invalid",
			failureParseReason: "field_count", cleanupReason: "response_invalid",
			cleanupParseReason: "quote",
			failureParseShape: {
				fieldCount: 5, quoteMask: 16, presenceMask: 1,
				stateClass: "connecting", lineClass: "none", singleFieldClass: "none"
			},
			cleanupParseShape: {
				fieldCount: 0, quoteMask: 0, presenceMask: 4,
				stateClass: "none", lineClass: "missing", singleFieldClass: "none"
			}
		};
		globalThis.fetch = async (path) => new Response(JSON.stringify(
			path === "/api/config" ? { csrfToken: "csrf" } : responseInvalid
		), { status: 200, headers: { "Content-Type": "application/json" } });
		await api.loadSnapshot();
		const annotated = await api.runPushTest(0, undefined, 1000);
		assert.deepEqual([
			annotated.failureReason, annotated.failureParseReason,
			annotated.cleanupReason, annotated.cleanupParseReason,
			annotated.failureParseShape.stateClass, annotated.cleanupParseShape.lineClass
		], ["response_invalid", "field_count", "response_invalid", "quote", "connecting", "missing"]);
		const responseRead = {
			...responseInvalid,
			transportPath: "cellular", dispatchAttempted: true, failureStage: "response",
			failureResponseReason: "http_parse"
		};
		globalThis.fetch = async (path) => new Response(JSON.stringify(
			path === "/api/config" ? { csrfToken: "csrf" } : responseRead
		), { status: 200, headers: { "Content-Type": "application/json" } });
		await api.loadSnapshot();
		assert.equal((await api.runPushTest(0, undefined, 1000)).failureResponseReason, "http_parse");
		for (const invalidResponse of [
			{ ...responseRead, failureResponseReason: "not-a-reason" },
			{ ...responseRead, failureResponseReason: 4 },
			{ ...responseRead, failureStage: "http" },
			{ ...responseRead, success: true },
			{ ...responseRead, done: false }
		]) {
			globalThis.fetch = async (path) => new Response(JSON.stringify(
				path === "/api/config" ? { csrfToken: "csrf" } : invalidResponse
			), { status: 200, headers: { "Content-Type": "application/json" } });
			await api.loadSnapshot();
			await assert.rejects(api.runPushTest(0, undefined, 1000), /Invalid push test response/);
		}
		for (const singleFieldClass of ["zero", "nonzero", "non_numeric"]) {
			const singleFieldResponse = {
				...responseInvalid,
				failureParseShape: { fieldCount: 1, quoteMask: 0, presenceMask: 4,
					stateClass: "none", lineClass: "none", singleFieldClass }
			};
			globalThis.fetch = async (path) => new Response(JSON.stringify(
				path === "/api/config" ? { csrfToken: "csrf" } : singleFieldResponse
			), { status: 200, headers: { "Content-Type": "application/json" } });
			await api.loadSnapshot();
			assert.equal((await api.runPushTest(0, undefined, 1000)).failureParseShape.singleFieldClass,
				singleFieldClass);
		}

		const cleanupMessages = [
			"HTTPS cleanup socket close failed",
			"HTTPS cleanup SSL config restore failed",
			"HTTPS cleanup autofree config restore failed",
			"HTTPS cleanup encoding config restore failed",
			"HTTPS cleanup PDP deactivate failed",
			"HTTPS cleanup PDP profile restore failed"
		];
		for (const cleanupMessage of cleanupMessages) {
			globalThis.fetch = async (path) => {
				if (path === "/api/config") return new Response(JSON.stringify({ csrfToken: "csrf" }), {
					status: 200, headers: { "Content-Type": "application/json" }
				});
				return new Response(JSON.stringify({ ...validPrimary, cleanupMessage }), {
					status: 200, headers: { "Content-Type": "application/json" }
				});
			};
			await api.loadSnapshot();
			assert.equal((await api.runPushTest(0, undefined, 1000)).cleanupMessage, cleanupMessage);
		}
		for (const cleanupMessage of ["HTTPS cleanup unknown", "HTTPS cleanup socket close failed "]) {
			globalThis.fetch = async (path) => {
				if (path === "/api/config") return new Response(JSON.stringify({ csrfToken: "csrf" }), {
					status: 200, headers: { "Content-Type": "application/json" }
				});
				return new Response(JSON.stringify({ ...validPrimary, cleanupMessage }), {
					status: 200, headers: { "Content-Type": "application/json" }
				});
			};
			await api.loadSnapshot();
			await assert.rejects(api.runPushTest(0, undefined, 1000), /Invalid push test response/);
		}

		for (const cleanupReason of ["terminal_failure", "poll_timeout"]) {
			globalThis.fetch = async (path) => {
				if (path === "/api/config") return new Response(JSON.stringify({ csrfToken: "csrf" }), {
					status: 200, headers: { "Content-Type": "application/json" }
				});
				return new Response(JSON.stringify({
					queued: false, running: false, done: true, success: false,
					message: "bounded cleanup", cleanupReason
				}), { status: 200, headers: { "Content-Type": "application/json" } });
			};
			await assert.rejects(api.runPushTest(0, undefined, 1000), /Invalid push test response/);
		}
		for (const status of [
			{ ...validPrimary, failureParseReason: "field_count" },
			{ ...validPrimary, failureReason: "command_failure", failureParseReason: "field_count" },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "unknown-value" },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 9, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "none" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "none", extra: 1 } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", singleFieldClass: "none" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "invalid", singleFieldClass: "none" } },
			{ ...validPrimary, failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
				stateClass: "unknown", lineClass: "none", singleFieldClass: "none" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "invalid" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: 4 } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "nonzero" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none" } },
			{ ...validPrimary, failureReason: "response_invalid", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 1, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "none" } },
			{ ...validPrimary, failureReason: "terminal_failure", failureParseReason: "field_count",
				failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
					stateClass: "unknown", lineClass: "none", singleFieldClass: "none" } },
			{ ...validPrimary, cleanupParseReason: "quote" },
			{ ...validPrimary, cleanupReason: "timeout", cleanupParseReason: "quote" },
			{ ...validPrimary, cleanupReason: "response_invalid", cleanupParseReason: "unknown-value" },
			{ ...validPrimary, cleanupReason: "response_invalid", cleanupParseReason: "quote",
				cleanupParseShape: { fieldCount: 9, quoteMask: 0, presenceMask: 4,
					stateClass: "none", lineClass: "missing", singleFieldClass: "none" } },
			{ ...validPrimary, cleanupReason: "response_invalid", cleanupParseReason: "quote",
				cleanupParseShape: { fieldCount: 0, quoteMask: 0, presenceMask: 4,
					stateClass: "none", lineClass: "missing", singleFieldClass: "invalid" } }
		]) {
			globalThis.fetch = async (path) => new Response(JSON.stringify(
				path === "/api/config" ? { csrfToken: "csrf" } : status
			), { status: 200, headers: { "Content-Type": "application/json" } });
			await api.loadSnapshot();
			await assert.rejects(api.runPushTest(0, undefined, 1000), /Invalid push test response/);
		}
	} finally {
		globalThis.fetch = previousFetch;
		try { await server?.close(); }
		finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});

test("push test validator accepts only complete terminal transport diagnostics", async () => {
	const previousMode = process.env.VITE_DEMO_MODE;
	const previousCwd = process.cwd();
	const previousFetch = globalThis.fetch;
	let server;
	try {
		delete process.env.VITE_DEMO_MODE;
		process.chdir(fileURLToPath(new URL("..", import.meta.url)));
		const { createServer } = await import("vite");
		server = await createServer({
			server: { middlewareMode: true }, appType: "custom", logLevel: "silent"
		});
		const api = await server.ssrLoadModule("/src/lib/api.ts");
		const valid = {
			queued: false, running: false, done: true, success: false,
			message: "HTTP rejected", transportPath: "wifi", dispatchAttempted: true,
			failureStage: "http", httpStatus: 503
		};
		globalThis.fetch = async (path) => new Response(JSON.stringify(
			path === "/api/config" ? { csrfToken: "csrf" } : valid
		), { status: 200, headers: { "Content-Type": "application/json" } });
		await api.loadSnapshot();
		const accepted = await api.runPushTest(0, undefined, 1000);
		assert.deepEqual([
			accepted.transportPath, accepted.dispatchAttempted, accepted.failureStage, accepted.httpStatus
		], ["wifi", true, "http", 503]);
		const success = {
			queued: false, running: false, done: true, success: true,
			message: "Test push sent", transportPath: "wifi", dispatchAttempted: true,
			failureStage: "none", httpStatus: 204
		};
		globalThis.fetch = async (path) => new Response(JSON.stringify(
			path === "/api/config" ? { csrfToken: "csrf" } : success
		), { status: 200, headers: { "Content-Type": "application/json" } });
		await api.loadSnapshot();
		assert.equal((await api.runPushTest(0, undefined, 1000)).httpStatus, 204);
		const preflight = {
			queued: false, running: false, done: true, success: false,
			message: "Preflight failed", transportPath: "none", dispatchAttempted: false,
			failureStage: "preflight"
		};
		globalThis.fetch = async (path) => new Response(JSON.stringify(
			path === "/api/config" ? { csrfToken: "csrf" } : preflight
		), { status: 200, headers: { "Content-Type": "application/json" } });
		await api.loadSnapshot();
		assert.equal((await api.runPushTest(0, undefined, 1000)).failureStage, "preflight");

		const invalidStatuses = [
			{ ...valid, transportPath: "satellite" },
			{ ...valid, httpStatus: 99 },
			{ ...valid, dispatchAttempted: false },
			{ ...valid, dispatchAttempted: undefined },
			{ ...valid, queued: true, running: false, done: false, success: false },
			{ ...success, transportPath: "none" },
			{ ...success, dispatchAttempted: false },
			{ ...success, transportPath: undefined },
			{ ...success, dispatchAttempted: undefined },
			{ ...success, failureStage: undefined },
			{ ...success, httpStatus: undefined },
			{ ...success, httpStatus: 503 },
			{ ...success, failureStage: "http" },
			{ ...valid, transportPath: undefined },
			{ ...valid, dispatchAttempted: undefined },
			{ ...valid, failureStage: undefined },
			{ ...valid, transportPath: "none", dispatchAttempted: false, failureStage: "none" },
			{ ...valid, transportPath: "wifi", dispatchAttempted: true, failureStage: "none" },
			{ ...valid, transportPath: "none", dispatchAttempted: true }
		];
		for (const status of invalidStatuses) {
			globalThis.fetch = async (path) => new Response(JSON.stringify(
				path === "/api/config" ? { csrfToken: "csrf" } : status
			), { status: 200, headers: { "Content-Type": "application/json" } });
			await api.loadSnapshot();
			await assert.rejects(api.runPushTest(0, undefined, 1000), /Invalid push test response/);
		}
	} finally {
		globalThis.fetch = previousFetch;
		try { await server?.close(); }
		finally {
			process.chdir(previousCwd);
			if (previousMode === undefined) delete process.env.VITE_DEMO_MODE;
			else process.env.VITE_DEMO_MODE = previousMode;
		}
	}
});

test("CI isolates release credentials from build lifecycle code", () => {
	const workflow = readFileSync(new URL("../../.github/workflows/build.yml", import.meta.url), "utf8");
	const [beforeRelease, release = ""] = workflow.split("\n  release:");
	const [build, prerelease = ""] = beforeRelease.split("\n  prerelease:");
	assert.match(workflow, /permissions:\n  contents: read/);
	assert.match(build, /build:\n    permissions:\n      contents: read/);
	assert.match(build, /outputs:\n      version: \$\{\{ steps\.version\.outputs\.version \}\}/);
	assert.match(build, /persist-credentials: false/);
	assert.doesNotMatch(build, /softprops\/action-gh-release/);
	assert.doesNotMatch(build, /OTA_SIGNING_PRIVATE_KEY/);
	assert.match(prerelease, /github\.event_name == 'push' && github\.ref == 'refs\/heads\/develop'/);
	assert.match(prerelease, /--prerelease/);
	assert.doesNotMatch(prerelease, /release upload|--clobber/);
	assert.doesNotMatch(prerelease, /OTA_SIGNING_PRIVATE_KEY/);
	assert.match(release, /needs: build/);
	assert.match(release, /github\.event_name == 'push'[\s\S]*startsWith\(github\.ref, 'refs\/tags\/v'\)[\s\S]*ota_runtime_ready == 'true'/);
	assert.match(release, /environment: release/);
	assert.match(release, /permissions:\n      contents: write/);
	assert.match(release, /actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\.3\.0/);
	assert.match(release, /OTA_SIGNING_PRIVATE_KEY: \$\{\{ secrets\.OTA_SIGNING_PRIVATE_KEY \}\}/);
	assert.match(release, /sha256sum --check/);
	assert.match(release, /--expected-public-sha256/);
	assert.match(release, /needs\.build\.outputs\.version/);
	assert.doesNotMatch(release, /release upload|--clobber/);
	assert.doesNotMatch(release, /npm/);
});

test("provisioning scan waits for the asynchronous result", async () => {
	const html = readFileSync(new URL("../static/provisioning.html", import.meta.url), "utf8");
	const script = html.match(/<script>([\s\S]*)<\/script>/)?.[1];
	assert.ok(script);

	const elements = new Map(["sel", "scanBtn", "ssid", "pass", "saveBtn", "msg"].map((id) => [id, {
		value: "", textContent: "", disabled: false, className: "", children: [],
		replaceChildren(...children) { this.children = children; },
		appendChild(child) { this.children.push(child); },
		focus() {}
	}]));
	const timers = [];
	let fetchCount = 0;
	const requestedPaths = [];
	const responses = [
		{ busy: "1", ready: "0", body: [] },
		{ busy: "0", ready: "1", body: [{ ssid: "Office", rssi: -48, enc: 1 }] }
	];
	const context = {
		document: {
			getElementById: (id) => elements.get(id),
			createElement: () => ({ value: "", textContent: "" })
		},
		fetch: async (path) => {
			requestedPaths.push(path);
			const response = responses[Math.min(fetchCount++, responses.length - 1)];
			return {
				ok: true,
				headers: { get: (name) => name === "X-WiFi-Scan-Busy" ? response.busy : response.ready },
				json: async () => response.body
			};
		},
		setTimeout: (callback) => { timers.push(callback); },
		setInterval: () => 1,
		clearInterval: () => {}
	};
	runInNewContext(script, context);
	context.scan();
	await new Promise(setImmediate);
	assert.equal(timers.length, 1);
	timers.shift()();
	await new Promise(setImmediate);

	assert.equal(fetchCount, 2);
	assert.doesNotMatch(requestedPaths[0], /poll=1/);
	assert.match(requestedPaths[1], /poll=1/);
	assert.equal(elements.get("sel").children[1].value, "Office");
	assert.equal(elements.get("scanBtn").disabled, false);
});
