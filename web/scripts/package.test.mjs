import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
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
