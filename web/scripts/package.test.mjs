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
