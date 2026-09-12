import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import puppeteer from "puppeteer-core";
import { createApp } from "../server.mjs";

const ROOT = resolve(new URL("../..", import.meta.url).pathname);
const WEB_ROOT = process.env.UI_BROWSER_WEB_ROOT ?? join(ROOT, "web", "build");
const OPENAPI_PATH = join(ROOT, "dev_doc", "openapi.json");
const ROUTES = ["connection", "diagnostics", "maintenance", "advanced"];
const browserCandidates = [
	process.env.CHROME_BIN,
	"/opt/brave.com/brave/brave",
	"/usr/bin/google-chrome",
	"/usr/bin/chromium",
	"/usr/bin/chromium-browser"
].filter((candidate) => candidate && existsSync(candidate));
const browserExecutable = browserCandidates[0];
const browserAvailable = Boolean(process.env.UI_BROWSER_URL || browserExecutable);

test("heartbeat save reaches terminal feedback above its button without collapsing the form", { skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async (t) => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		// Cold navigation can exceed 30 s on the local host; action deadlines stay below.
		page.setDefaultNavigationTimeout(60000);
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll('[data-slot="accordion-trigger"]')].find((button) => button.textContent.includes("Heartbeat")).click());
		await waitForAccordionContent(page, "#heartbeat-form");
		let rejectSave = false;
		let freshCa = false;
		const delayedCa = [];
		await t.test("save settles in the open form", { timeout: 10000 }, async () => {
		const storedPush = await page.$eval("#push-global-enabled", (button) => button.getAttribute("aria-checked"));
		await page.$eval("#push-global-enabled", (button) => button.click());
		await page.setRequestInterception(true);
		page.on("request", (request) => {
			if (new URL(request.url()).pathname === "/save" && rejectSave) void request.respond({ status: 503, contentType: "text/plain", body: "Unavailable" });
			else if (new URL(request.url()).pathname === "/api/push/ca/status") {
				if (freshCa) void request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true, code: "PUSH_CA_STATUS", data: { configured: true, sha256: "a".repeat(64) }, detail: "" }) });
				else delayedCa.push(request);
			}
			else void request.continue();
		});
		const responses = [];
		page.on("response", (response) => { if (new URL(response.url()).pathname === "/save") responses.push(response.status()); });
		const accepted = page.waitForResponse((response) => new URL(response.url()).pathname === "/save", { timeout: 5000 });
		await page.$eval("#heartbeat-form", (form) => form.requestSubmit());
		assert.equal((await accepted).status(), 202);
		await page.waitForFunction(() => [...document.querySelectorAll('[role="status"]')].some((element) => element.textContent.includes("Configuration saved")), { timeout: 5000 });
		await page.waitForFunction(() => !document.querySelector('button[form="heartbeat-form"]')?.disabled, { timeout: 5000 });
		assert.deepEqual(responses, [202]);
		assert.ok(await page.$eval("#heartbeat-form", (form) => form.getBoundingClientRect().height > 0), "successful save must leave the edited form open");
		const position = await page.$eval("#heartbeat-form", (form) => {
			const region = form.parentElement;
			const result = [...region.querySelectorAll('[role="status"]')].find((element) => element.textContent.includes("Configuration saved"));
			const button = region.querySelector('button[form="heartbeat-form"]');
			return { result: result?.textContent, busy: button?.disabled, resultBottom: result?.getBoundingClientRect().bottom, buttonTop: button?.getBoundingClientRect().top };
		});
		assert.ok(position.result.includes("Configuration saved"));
		assert.equal(position.busy, false);
		assert.ok(position.resultBottom <= position.buttonTop, "heartbeat feedback must appear above Save");
		assert.equal(await page.$eval("#push-global-enabled", (button) => button.getAttribute("aria-checked")), storedPush === "true" ? "false" : "true", "a successful heartbeat refresh must preserve the unrelated push-switch draft");
		assert.ok(delayedCa.length > 0, "Save must settle while its background certificate reads remain pending");
		await Promise.all(delayedCa.filter((request) => new URL(request.url()).searchParams.get("channel") !== "0").map((request) => request.respond({ status: 503, contentType: "text/plain", body: "Unavailable" })));
		});
		await t.test("rejected save replaces success with terminal error", { timeout: 10000 }, async () => {
			rejectSave = true;
			await page.$eval("#heartbeat-form", (form) => form.requestSubmit());
			await page.waitForFunction(() => document.querySelector("#heartbeat-form")?.parentElement.querySelector('[role="alert"]')?.textContent.includes("Request failed"), { timeout: 5000 });
			const error = await page.$eval("#heartbeat-form", (form) => {
				const result = form.parentElement.querySelector('[role="alert"]');
				const button = form.parentElement.querySelector('button[form="heartbeat-form"]');
				return { text: result.textContent, button: button.textContent.trim(), disabled: button.disabled, above: result.getBoundingClientRect().bottom <= button.getBoundingClientRect().top };
			});
			assert.equal(error.button, "Save");
			assert.equal(error.disabled, false);
			assert.equal(error.above, true);
			assert.doesNotMatch(error.text, /Configuration saved/);
		});
		await t.test("late certificate reads cannot replace a newer configured state", { timeout: 10000 }, async () => {
			freshCa = true;
			await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "4G delivery and certificates").click());
			await waitForAccordionContent(page, "#push-cellular-url-0");
			await page.$eval("#push-cellular-url-0", (input) => [...input.closest('[data-slot="card"]').querySelectorAll("button")].find((button) => button.textContent.trim() === "Check and set up").click());
			await page.waitForFunction(() => document.querySelector("#push-cellular-url-0").closest('[data-slot="card"]').textContent.includes("Certificate configured"), { timeout: 5000 });
			const old = delayedCa.find((request) => new URL(request.url()).searchParams.get("channel") === "0");
			assert.ok(old);
			const response = page.waitForResponse((reply) => reply.request() === old, { timeout: 5000 });
			await old.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true, code: "PUSH_CA_STATUS", data: { configured: false, sha256: "" }, detail: "" }) });
			await (await response).json();
			await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
			assert.ok(await page.$eval("#push-cellular-url-0", (input) => input.closest('[data-slot="card"]').textContent.includes("Certificate configured")));
		});
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("heartbeat refresh failure preserves successful feedback and unrelated drafts", { skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async (t) => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		page.setDefaultNavigationTimeout(60000);
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll('[data-slot="accordion-trigger"]')].find((button) => button.textContent.includes("Heartbeat")).click());
		await waitForAccordionContent(page, "#heartbeat-form");
		await t.test("save remains successful when its following read fails", { timeout: 10000 }, async () => {
			const before = await page.$eval("#push-global-enabled", (button) => button.getAttribute("aria-checked"));
			await page.$eval("#push-global-enabled", (button) => button.click());
			await page.setRequestInterception(true);
			let reads = 0;
			page.on("request", (request) => {
				if (new URL(request.url()).pathname === "/api/config") { reads++; return void request.respond({ status: 503, contentType: "text/plain", body: "Unavailable" }); }
				void request.continue();
			});
			await page.$eval("#heartbeat-form", (form) => form.requestSubmit());
			await page.waitForFunction(() => document.body.textContent.includes("HTTP 503"), { timeout: 5000 });
			assert.equal(reads, 1, "failed refresh must not automatically repeat a read or save");
			assert.ok(await page.$eval("#heartbeat-form", (form) => form.parentElement.textContent.includes("Configuration saved")));
			assert.equal(await page.$eval("#push-global-enabled", (button) => button.getAttribute("aria-checked")), before === "true" ? "false" : "true");
			assert.equal(await page.$eval('button[form="heartbeat-form"]', (button) => button.textContent.trim()), "Save");
		});
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("push channel saves validate active provider fields before sending any settings", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.includes("Push channels") && button.hasAttribute("aria-expanded")).click());
		await waitForAccordionContent(page, "#push-url-0");
		const before = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		const saves = [];
		page.on("request", (request) => { if (new URL(request.url()).pathname === "/save") saves.push(request.postData()); });
		await page.evaluate(() => { window.invalidFields = []; document.addEventListener("invalid", (event) => window.invalidFields.push(event.target.id), true); });
		await page.$eval("#push-enabled-0", (button) => button.click());
		await page.$eval("#push-name-0", (input) => { input.value = "Unsaved draft"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#push-url-0", (input) => [...input.closest('[data-slot="accordion-content"]').querySelectorAll("button")].find((button) => button.textContent.trim() === "Save").click());
		assert.deepEqual(await page.evaluate(() => window.invalidFields), ["push-url-0"], "Save must report the missing active endpoint before invoking /save");
		assert.equal(saves.length, 0);
		assert.deepEqual(await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels), before, "invalid edits must leave all five stored channels unchanged");
		await page.$eval("#push-url-0", (input) => { input.value = "not a URL"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.focus("#push-url-0");
		await page.keyboard.press("Enter");
		assert.equal(await page.evaluate(() => window.invalidFields.at(-1)), "push-url-0");
		assert.equal(saves.length, 0);
		await page.select("#push-type-0", "10");
		await page.$eval("#push-key1-0", (input) => { input.value = "chat-id"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.focus("#push-key1-0");
		await page.keyboard.press("Enter");
		assert.equal(await page.evaluate(() => window.invalidFields.at(-1)), "push-key2-0", "Telegram requires its token but permits the default endpoint");
		await page.select("#push-type-0", "7");
		await page.$eval("#push-url-0", (input) => { input.value = "https://example.test/hook"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#push-body-0", (input) => { input.value = ""; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#push-url-0", (input) => [...input.closest('[data-slot="accordion-content"]').querySelectorAll("button")].find((button) => button.textContent.trim() === "Save").click());
		assert.equal(await page.evaluate(() => window.invalidFields.at(-1)), "push-body-0");
		assert.equal(saves.length, 0);
		await page.select("#push-type-0", "6");
		await page.$eval("#push-key1-0", (input) => { input.value = "synthetic-send-key"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.focus("#push-key1-0");
		await Promise.all([
			page.waitForResponse((response) => new URL(response.url()).pathname === "/save", { timeout: 5000 }),
			page.keyboard.press("Enter")
		]);
		await page.waitForFunction(() => document.body.textContent.includes("Configuration saved"), { timeout: 5000 });
		assert.equal(saves.length, 1, "only the valid provider draft is submitted");
		const after = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		assert.equal(after[0].type, 6);
		assert.equal(after[0].name, "Unsaved draft");
		assert.deepEqual(after.slice(1), before.slice(1));
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("a masked configured channel saves without validating another tab's incomplete draft", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	const base = `http://127.0.0.1:${server.address().port}`;
	let browser, page, userDataDir, shared;
	try {
		const accepted = await (await fetch(`${base}/save`, { method: "POST", headers: { "X-CSRF-Token": "mock-csrf-token" }, body: new URLSearchParams({ push4en: "on", push4type: "9", push4url: "https://example.test/message", push4key1: "synthetic-token" }) })).json();
		await fetch(`${base}/api/jobs?id=${accepted.data.jobId}`);
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, base, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.includes("Push channels") && button.hasAttribute("aria-expanded")).click());
		await waitForAccordionContent(page, "#push-url-0");
		await page.$eval("#push-enabled-0", (button) => button.click());
		await page.$eval("#push-url-0", (input) => input.closest('[data-slot="accordion-content"]').querySelectorAll('[role="tab"]')[4].click());
		await page.waitForSelector("#push-url-4");
		assert.equal(await page.$eval("#push-url-4", (input) => input.value), "");
		assert.equal(await page.$eval("#push-key1-4", (input) => input.value), "");
		await page.$eval("#push-name-4", (input) => { input.value = "Renamed masked provider"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await Promise.all([
			page.waitForResponse((response) => new URL(response.url()).pathname === "/save", { timeout: 5000 }),
			page.click('button[form="push-form-4"]')
		]);
		await page.waitForFunction(() => document.body.textContent.includes("Configuration saved"), { timeout: 5000 });
		const channels = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		assert.deepEqual(channels.slice(0, 4).map((channel) => channel.enabled), [false, false, false, false]);
		assert.deepEqual([channels[4].enabled, channels[4].urlSet, channels[4].key1Set, channels[4].name], [true, true, true, "Renamed masked provider"]);
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("an invalid cellular URL sends no configuration request", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "4G delivery and certificates").click());
		await waitForAccordionContent(page, "#push-cellular-url-0");
		const before = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		let saves = 0;
		page.on("request", (request) => { if (new URL(request.url()).pathname === "/save") saves++; });
		await page.$eval("#push-cellular-url-0", (input) => { input.value = "invalid cellular URL"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.click('button[form="push-cellular-form-0"]');
		assert.equal(await page.$eval("#push-cellular-url-0", (input) => input.getAttribute("aria-invalid")), "true");
		assert.equal(saves, 0);
		assert.deepEqual(await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels), before);
		await page.$eval("#push-cellular-url-0", (input) => [...input.closest("form").querySelectorAll("button")].find((button) => button.textContent.trim() === "Clear saved override").click());
		assert.deepEqual(await page.$eval("#push-cellular-url-0", (input) => [input.value, input.validity.valid, input.getAttribute("aria-invalid")]), ["", true, null], "clearing the override also clears its validation error");
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("cellular saves preserve both saved providers and unsaved provider drafts", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	const base = `http://127.0.0.1:${server.address().port}`;
	let browser, page, userDataDir, shared;
	try {
		const accepted = await (await fetch(`${base}/save`, { method: "POST", headers: { "X-CSRF-Token": "mock-csrf-token" }, body: new URLSearchParams({ push0en: "on", push0type: "9", push0name: "Saved provider", push0url: "https://example.test/message", push0key1: "synthetic-token" }) })).json();
		await fetch(`${base}/api/jobs?id=${accepted.data.jobId}`);
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, base, "#notifications");
		await page.waitForSelector("#push-global-enabled");
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.includes("Push channels") && button.hasAttribute("aria-expanded")).click());
		await waitForAccordionContent(page, "#push-url-0");
		await page.$eval("#push-url-0", (input) => { input.value = "invalid provider draft"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#push-name-0", (input) => { input.value = "Unsaved provider name"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "4G delivery and certificates").click());
		await waitForAccordionContent(page, "#push-cellular-url-0");
		const before = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		const saves = [];
		page.on("request", (request) => { if (new URL(request.url()).pathname === "/save") saves.push(request.postData()); });
		await page.$eval("#push-cellular-url-0", (input) => { input.value = "https://cell.example.test/message"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#push-cellular-enabled-0", (button) => button.click());
		await page.focus("#push-cellular-url-0");
		await Promise.all([
			page.waitForResponse((response) => new URL(response.url()).pathname === "/save", { timeout: 5000 }),
			page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config", { timeout: 5000 }),
			page.keyboard.press("Enter")
		]);
		await page.waitForSelector("#push-global-enabled", { timeout: 5000 });
		const after = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.pushChannels);
		assert.deepEqual(after, before.map((channel, index) => index ? channel : { ...channel, cellularEnabled: false, cellularUrlSet: true }));
		assert.deepEqual([...new URLSearchParams(saves[0]).keys()].sort(), ["push0cellularEnabled", "push0cellularUrl"]);
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.includes("Push channels") && button.hasAttribute("aria-expanded")).click());
		await waitForAccordionContent(page, "#push-url-0");
		assert.equal(await page.$eval("#push-url-0", (input) => input.value), "invalid provider draft");
		assert.equal(await page.$eval("#push-name-0", (input) => input.value), "Unsaved provider name");
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("mobile CSV editor preserves quoted text, tests first-match routing, and saves only on request", { timeout: 45000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 390, height: 844, hasTouch: true });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#messaging");
		await page.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent.trim() === "Forwarding rules"));
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Forwarding rules").click());
		await waitForAccordionContent(page, "#forward-rules");
		let saves = 0;
		page.on("request", (request) => { if (new URL(request.url()).pathname === "/save") saves++; });
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Add rule").click());
		await page.type("#rule-pattern-0", 'a,"b"');
		await page.$eval("#rule-actions-0", (input) => { input.value = "email,2"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		assert.equal(await page.$eval("#forward-rules", (input) => input.value), 'kw,"a,""b""","email,2",1');
		await page.type("#rule-test-sender", "+123456");
		await page.type("#rule-test-message", 'a,"b"');
		const [previewAccepted] = await Promise.all([
			page.waitForResponse((response) => new URL(response.url()).pathname === "/api/rules/preview" && response.request().method() === "POST", { timeout: 5000 }),
			page.click("#rule-test")
		]);
		assert.equal(previewAccepted.status(), 202);
		await page.waitForSelector("#rule-preview-result");
		assert.match(await page.$eval("#rule-preview-result", (region) => region.textContent), /First match: line 1/);
		assert.deepEqual(await page.$$eval("[data-rule-actions] li", (items) => items.map((item) => item.textContent)), ["Email", "Push channel 2"]);
		assert.equal(saves, 0);
		await page.$eval("#forward-rules", (input) => { input.value = 'kw,"broken,email'; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.waitForFunction(() => document.querySelector('button[form="forward-rules-form"]').disabled);
		assert.equal(await page.$eval("#rule-test", (button) => button.disabled), true);
		assert.equal(await page.$("#rule-preview-result"), null, "stale results must disappear after an edit");
		await page.$eval("#forward-rules", (input) => { input.value = 'kw,"line1\nline2",drop\nkw,OTP,email'; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.$eval("#rule-test-message", (input) => { input.value = "OTP"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		await page.click("#rule-test");
		await page.waitForFunction(() => document.querySelector("#rule-preview-result")?.textContent.includes("First match: line 3"));
		await page.click('button[form="forward-rules-form"]');
		await page.waitForFunction(() => document.body.textContent.includes("Configuration saved"), { timeout: 5000 }).catch(async (error) => { throw new Error(`${error.message}: ${await page.$eval("#forward-rules-form", (form) => form.parentElement.textContent)}`); });
		assert.equal(saves, 1);
		const saved = await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.forwardRules);
		assert.equal(saved, '#!forward-rules-csv-v1\nkw,"line1\nline2",drop\nkw,OTP,email');
		assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "the editor must fit a narrow viewport");
		await page.evaluate(async () => {
			const response = await fetch("/save", { method: "POST", headers: { "X-CSRF-Token": "mock-csrf-token" }, body: new URLSearchParams({ forwardRules: "kw\tA,B\temail,1" }) });
			const accepted = await response.json();
			await fetch(`/api/jobs?id=${accepted.data.jobId}`);
		});
		await page.reload({ waitUntil: "domcontentloaded" });
		await page.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent.trim() === "Forwarding rules"));
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Forwarding rules").click());
		await page.waitForSelector("#forward-rules");
		assert.equal(await page.$eval("#forward-rules", (input) => input.value), "kw\tA,B\temail,1");
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Convert to CSV").click());
		assert.equal(await page.$eval("#forward-rules", (input) => input.value), 'kw,"A,B","email,1",1');
		assert.equal(await page.evaluate(async () => (await (await fetch("/api/config")).json()).config.forwardRules), "kw\tA,B\temail,1", "conversion remains a draft until saved");
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("keepalive load failure stays visible and retry restores its form", { skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async (t) => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		page.setDefaultNavigationTimeout(60000);
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await page.setRequestInterception(true);
		let fail = true;
		let intercept = null;
		page.on("request", (request) => {
			if (intercept?.(request)) return;
			if (new URL(request.url()).pathname === "/api/keepalive" && fail) { return void request.respond({ status: 503, contentType: "text/plain", body: "Service unavailable" }); }
			void request.continue();
		});
		const failed = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/keepalive" && response.status() === 503, { timeout: 60000 });
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#device/connection");
		await failed;
		await t.test("initial error and retry remain available", { timeout: 10000 }, async () => {
		await page.waitForFunction(() => [...document.querySelectorAll('[role="alert"]')].some((element) => element.textContent.includes("Request failed")), { timeout: 1000 }).catch(() => {});
		assert.ok(await page.evaluate(() => [...document.querySelectorAll('[role="alert"]')].some((element) => element.textContent.includes("Request failed"))), "failed initial keepalive load must expose its error even without status data");
		fail = false;
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Retry").click());
		await page.waitForSelector("#keepalive-url", { timeout: 5000 });
		assert.equal(await page.$eval("#keepalive-enabled", (button) => button.getAttribute("aria-checked")), "false");
		});
		await t.test("run feedback belongs to Run, not Save", { timeout: 10000 }, async () => {
			let held;
			const started = new Promise((resolve) => { intercept = (request) => {
				if (new URL(request.url()).searchParams.get("action") !== "run") return false;
				held = request; resolve(); return true;
			}; });
			await page.$eval('[data-keepalive-operation="run"] button', (button) => button.click());
			await started;
			assert.equal(await page.$eval('[data-keepalive-operation="save"] button', (button) => button.textContent.trim()), "Save");
			assert.equal(await page.$eval('[data-keepalive-operation="save"] button', (button) => button.getAttribute("aria-busy")), "false");
			assert.equal(await page.$eval('[data-keepalive-operation="run"] button', (button) => button.getAttribute("aria-busy")), "true");
			intercept = null;
			await held.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true, message: "" }) });
			await page.waitForFunction(() => !document.querySelector('[data-keepalive-operation="run"] button').disabled, { timeout: 5000 });
			assert.ok(await page.$eval('[data-keepalive-operation="run"]', (region) => region.querySelector('[role="status"]').getBoundingClientRect().bottom <= region.querySelector("button").getBoundingClientRect().top));
		});
		await t.test("successful Save stops its spinner while refreshing status", { timeout: 10000 }, async () => {
			let held;
			const started = new Promise((resolve) => { intercept = (request) => {
				if (new URL(request.url()).pathname !== "/api/keepalive" || request.method() !== "GET") return false;
				held = request; resolve(); return true;
			}; });
			await page.$eval('[data-keepalive-operation="save"] button', (button) => button.click());
			await started;
			const saved = await page.$eval('[data-keepalive-operation="save"]', (region) => {
				const button = region.querySelector("button");
				return { text: button.textContent.trim(), busy: button.getAttribute("aria-busy"), disabled: button.disabled, success: region.querySelector('[role="status"]').textContent.includes("Configuration saved") };
			});
			assert.deepEqual(saved, { text: "Save", busy: "false", disabled: true, success: true });
			intercept = null;
			await held.continue();
			await page.waitForFunction(() => !document.querySelector('[data-keepalive-operation="save"] button').disabled, { timeout: 5000 });
		});
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

// The journey includes cold Chromium and application startup; probe response still has a 5 s deadline.
test("mobile keepalive uses HTTP without certificates and HTTPS with a dedicated certificate target", { timeout: 45000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 390, height: 844, hasTouch: true });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		const calls = [];
		await page.setRequestInterception(true);
		page.on("request", (request) => {
			const path = new URL(request.url()).pathname;
			if (path.startsWith("/api/keepalive") || (path.startsWith("/api/push") && request.method() !== "GET")) calls.push(path);
			if (path === "/api/keepalive/ca/probe") return void request.respond({ status: 409, contentType: "application/json", body: JSON.stringify({ success: false, code: "PUSH_CA_PROBE_FAILED", data: {}, detail: "" }) });
			void request.continue();
		});
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#device/connection");
		await page.waitForSelector("#keepalive-url");
		assert.match(await page.$eval("#keepalive-url", (input) => input.value), /^http:\/\//);
		assert.match(await page.$eval("#keepalive-url", (input) => input.closest("form").parentElement.textContent), /HTTP downloads are unencrypted/);
		assert.equal(await page.evaluate(() => [...document.querySelectorAll("button")].some((button) => button.textContent.trim() === "Check and set up certificate")), false);
		assert.equal(await page.$eval("#keepalive-enabled", (input) => input.getAttribute("aria-checked")), "false");
		await page.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent.trim() === "Run once using mobile data" && !button.disabled));
		await Promise.all([
			page.waitForResponse((response) => new URL(response.url()).pathname === "/api/keepalive" && response.request().method() === "POST", { timeout: 5000 }),
			page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Run once using mobile data").click())
		]);
		await page.waitForFunction(() => document.body.textContent.includes("Keepalive completed"), { timeout: 5000 });
		assert.equal(calls.some((path) => path.includes("/ca/")), false, "the synthetic HTTP transfer must not probe or install a CA");
		await page.$eval("#keepalive-url", (input) => { input.value = "https://example.test/payload"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		assert.equal(await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Check and set up certificate").disabled), true, "save the URL before probing its certificate");
		await page.$eval("#keepalive-url", (input) => input.closest("form").querySelector('button[type="submit"]').click());
		await page.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent.trim() === "Check and set up certificate" && !button.disabled));
		const config = await page.evaluate(async () => (await (await fetch("/api/keepalive")).json()));
		assert.equal(config.url, "https://example.test/payload");
		assert.equal(config.enabled, false, "saving a URL must not enable scheduled cellular traffic");
		const probeResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/keepalive/ca/probe", { timeout: 5000 });
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Check and set up certificate").click());
		await probeResponse.catch(async (error) => { throw new Error(`${error.message}; calls=${JSON.stringify(calls)}; ${await page.$eval("#keepalive-url", (input) => input.closest("form").textContent)}`); });
		await page.waitForFunction(() => document.querySelector("#keepalive-url")?.closest("form").textContent.includes("Cannot retrieve the server certificate"));
		assert.ok(calls.includes("/api/keepalive/ca/probe"));
		assert.equal(calls.some((path) => path.startsWith("/api/push")), false, "keepalive setup must not require a notification channel");
		assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("roaming diagnostics expose raw values by keyboard and touch", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 1280, height: 800 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await page.setRequestInterception(true);
		page.on("request", (request) => {
			if (new URL(request.url()).pathname === "/api/jobs") return void request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ id: 1, type: "query", state: "succeeded", result: { success: true, code: "ACTION_QUERY_OK", data: { registration: 5, cesq: "-70,-11,31" }, detail: "" } }) });
			void request.continue();
		});
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#device/diagnostics");
		await waitForAccordionContent(page, '[data-device-action="diagnostics-network"]');
		await page.$eval('[data-device-action="diagnostics-network"]', (button) => button.click());
		await page.waitForSelector('[title="registration: 5"]');
		assert.equal(await page.$$eval("dd details", (elements) => elements.length), 0, "human values must not have per-field disclosure controls");
		assert.match(await page.$eval('[title="registration: 5"]', (value) => value.textContent), /Registered on a roaming network/);
		assert.doesNotMatch(await page.$eval('[title="registration: 5"]', (value) => value.textContent), /Original value/);
		assert.deepEqual(await page.$$eval('[data-signal-metric] dt', (labels) => labels.map((label) => label.textContent)), ["RSRP", "RSRQ", "CSQ"]);
		assert.match(await page.$eval('[data-signal-metric]:last-child dd', (value) => value.textContent), /≥ −51 dBm/);
		assert.equal((await page.$$('[data-result-raw-trigger]')).length, 1);
		await page.focus('[data-result-raw-trigger]');
		await page.keyboard.press("Enter");
		await page.waitForSelector('dialog[data-result-raw][open]', { timeout: 1000 });
		assert.equal(await page.$eval('dialog[data-result-raw] textarea', (raw) => raw.value), 'registration: 5\ncesq: "-70,-11,31"');
		await page.keyboard.press("Escape");
		await page.waitForFunction(() => !document.querySelector('dialog[data-result-raw]').open, { timeout: 1000 });
		assert.equal(await page.$eval('[data-result-raw-trigger]', (button) => button === document.activeElement), true);
		await page.setViewport({ width: 390, height: 844 });
		const metricRows = await page.$$eval("[data-signal-metric]", (rows) => rows.map((row) => ({ top: row.getBoundingClientRect().top, bottom: row.getBoundingClientRect().bottom })));
		assert.ok(metricRows[1].top >= metricRows[0].bottom && metricRows[2].top >= metricRows[1].bottom);
		await waitForAccordionContent(page, '[data-result-raw-trigger]');
		await page.tap('[data-result-raw-trigger]');
		await page.waitForSelector('dialog[data-result-raw][open]', { timeout: 1000 });
		assert.equal(await page.$eval('dialog[data-result-raw] textarea', (raw) => raw.value), 'registration: 5\ncesq: "-70,-11,31"');
		assert.ok(await page.$eval('dialog[data-result-raw]', (dialog) => dialog.getBoundingClientRect().width <= innerWidth));
		assert.equal(await page.$eval('dialog[data-result-raw] textarea', (raw) => { raw.focus(); raw.select(); return raw.readOnly && raw.selectionEnd === raw.value.length && getComputedStyle(raw).fontFamily.includes("mono"); }), true);
		await page.tap('dialog[data-result-raw] button');
		await page.waitForFunction(() => !document.querySelector('dialog[data-result-raw]').open, { timeout: 1000 });
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("firmware version and the project release link belong to the update section", { timeout: 30000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 390, height: 844 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await openRoute(page, "http://127.0.0.1:" + server.address().port, "#device/maintenance");
		await page.$eval('[data-device-action="maintenance-ota"]', (button) => { const trigger = button.closest('[data-slot="accordion-item"]').querySelector('[data-slot="accordion-trigger"]'); if (trigger.getAttribute("aria-expanded") !== "true") trigger.click(); });
		await waitForAccordionContent(page, '[data-firmware-version]');
		const version = await page.evaluate(async () => (await (await fetch("/api/config")).json()).status.firmwareVersion);
		assert.equal(await page.$eval('[data-firmware-version]', (value) => value.textContent), version);
		assert.equal(await page.$$eval('footer[aria-label="Firmware version"]', (footers) => footers.length), 0);
		assert.equal(await page.$eval('a[href="https://github.com/lekoOwO/sms_forwarding/releases"]', (link) => link.textContent), "project releases");
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("mobile long values, technical text and semantic alerts stay readable in both themes", { timeout: 45000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser, page, userDataDir, shared;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 390, height: 844 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "en"));
		await page.setRequestInterception(true);
		const longName = "Synthetic-device-name-with-a-long-readable-suffix";
		page.on("request", async (request) => {
			const path = new URL(request.url()).pathname;
			if (path === "/api/config") {
				const data = await (await fetch(request.url())).json();
				data.config.deviceName = longName;
				data.config.hostname = "synthetic-device-hostname-for-layout";
				data.status.wifiSsid = "Synthetic-network-name-1234567890";
				return void request.respond({ status: 200, contentType: "application/json", body: JSON.stringify(data) });
			}
			if (path === "/api/ota/state") return void request.respond({ status: 503, contentType: "application/json", body: "{}" });
			if (path === "/log") return void request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ entries: Array.from({ length: 50 }, (_, index) => ({ id: index + 1, message: "Synthetic diagnostic line " + index })), nextCursor: null, hasMore: false }) });
			void request.continue();
		});
		const base = "http://127.0.0.1:" + server.address().port;
		await openRoute(page, base, "#overview");
		await page.waitForSelector('[data-overview-group="identity"] dd');
		assert.equal(await page.$eval('[data-overview-group="identity"] dd', (value) => value.textContent), longName);
		assert.ok(await page.$$eval("[data-overview-group] dd", (values) => values.every((value) => getComputedStyle(value).whiteSpace !== "nowrap" && value.scrollWidth <= value.clientWidth)));
		const checkAlert = async (variant) => {
			const selector = '[data-slot="alert"].bg-alert-' + variant;
			await page.waitForSelector(selector);
			for (const dark of [false, true]) {
				await page.evaluate((enabled) => document.documentElement.classList.toggle("dark", enabled), dark);
				const measured = await page.$eval(selector, (alert) => {
					const description = alert.querySelector('[data-slot="alert-description"]');
					const canvas = document.createElement("canvas");
					canvas.width = canvas.height = 1;
					const context = canvas.getContext("2d");
					const rgb = (color) => { context.clearRect(0, 0, 1, 1); context.fillStyle = color; context.fillRect(0, 0, 1, 1); return [...context.getImageData(0, 0, 1, 1).data].slice(0, 3); };
					const luminance = (color) => rgb(color).map((channel) => { const value = channel / 255; return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4; }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
					const styles = getComputedStyle(alert);
					const foreground = luminance(getComputedStyle(description).color), background = luminance(styles.backgroundColor);
					return { contrast: (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05), role: alert.getAttribute("role"), icon: Boolean(alert.querySelector('svg[aria-hidden="true"]')), title: Boolean(alert.querySelector('[data-slot="alert-title"]')?.textContent.trim()) };
				});
				assert.ok(measured.contrast >= 4.5, variant + "/" + dark + ": contrast " + measured.contrast);
				assert.equal(measured.role, variant === "destructive" ? "alert" : "status");
				assert.ok(measured.icon && measured.title, "severity must not depend on color alone");
			}
		};
		await checkAlert("info");
		await openRoute(page, base, "#notifications");
		await page.waitForSelector("#heartbeat-form");
		await page.$eval("#heartbeat-form", (form) => { const trigger = form.closest('[data-slot="accordion-item"]').querySelector('[data-slot="accordion-trigger"]'); if (trigger.getAttribute("aria-expanded") !== "true") trigger.click(); });
		await waitForAccordionContent(page, "#heartbeat-form");
		await checkAlert("warning");
		await openRoute(page, base, "#security");
		await checkAlert("destructive");
		await openRoute(page, base, "#device/diagnostics");
		await Promise.all([page.waitForResponse((response) => new URL(response.url()).pathname === "/log", { timeout: 5000 }), page.locator('[data-device-action="diagnostics-logs-refresh"]').setTimeout(1000).click()]);
		await page.waitForSelector('textarea[aria-label="System logs"]', { timeout: 5000 });
		assert.ok(await page.$eval('textarea[aria-label="System logs"]', (field) => {
			field.focus(); field.select();
			const style = getComputedStyle(field);
			return field.readOnly && !field.disabled && document.activeElement === field && field.selectionEnd === field.value.length && style.fontFamily.includes("mono") && field.clientHeight >= 192 && field.clientHeight <= 448 && field.scrollHeight > field.clientHeight;
		}));
		await openRoute(page, base, "#device/advanced");
		assert.ok(await page.$eval('[data-device-action="advanced-at-terminal"] input', (input) => !input.spellcheck && input.autocapitalize === "none" && getComputedStyle(input).fontFamily.includes("mono")));
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("identity save replaces pending feedback after success, failure, retry, and lost response above its button", { timeout: 45000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	let browser;
	let page;
	let userDataDir;
	let shared = false;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 390, height: 844 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "zh-TW"));
		await openRoute(page, `http://127.0.0.1:${server.address().port}`, "#device/connection");
		await page.waitForSelector("#identity-form");
		await page.setRequestInterception(true);
		let receiveJob;
		let saveRequests = 0;
		page.on("request", (request) => {
			if (new URL(request.url()).pathname === "/save") saveRequests += 1;
			if (new URL(request.url()).pathname === "/api/jobs") receiveJob(request);
			else void request.continue();
		});
		for (const success of [true, false, true]) {
			const pendingJob = new Promise((resolve) => receiveJob = resolve);
			await page.$eval("#identity-form", (form) => form.requestSubmit());
			await page.waitForFunction(() => document.querySelector("#identity-form").parentElement.textContent.includes("儲存中"));
			const request = await pendingJob;
			const jobId = Number(new URL(request.url()).searchParams.get("id"));
			await request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({
				id: jobId, type: "config-save", state: success ? "succeeded" : "failed",
				result: { success, code: success ? "ACTION_CONFIG_SAVED" : "ACTION_CONFIG_SAVE_FAILED", data: {}, detail: "" }
			}) });
			const message = success ? "設定已儲存。" : "設定無法儲存。請重試，並在裝置重新啟動後確認。";
			await page.waitForFunction((expected) => {
				const region = document.querySelector("#identity-form")?.parentElement;
				return region?.textContent.includes(expected) && !region.textContent.includes("儲存中");
			}, { timeout: 5000 }, message).catch(() => {});
			assert.equal(await page.$eval("#identity-form", (form) =>
				form.parentElement.querySelector('[role="status"], [role="alert"]').textContent.includes("儲存中")), false,
				`terminal ${success ? "success" : "failure"} must replace pending feedback`);
			assert.ok(await page.$eval("#identity-form", (form, expected) => form.parentElement.textContent.includes(expected), message));
		}
		await page.evaluate(() => {
			const original = globalThis.setTimeout;
			globalThis.setTimeout = (callback, delay, ...args) => original(callback, delay === 90000 ? 100 : delay, ...args);
		});
		const lostJob = new Promise((resolve) => receiveJob = resolve);
		await page.$eval("#identity-form", (form) => form.requestSubmit());
		const lostRequest = await lostJob;
		await page.waitForFunction(() => document.querySelector("#identity-form").parentElement.textContent.includes("裝置未回傳操作結果"));
		assert.equal(saveRequests, 4, "an unknown result must not resubmit the save automatically");
		assert.equal(await page.$eval('button[form="identity-form"]', (button) => button.disabled), false);
		await lostRequest.abort().catch(() => {});
		const position = await page.$eval("#identity-form", (form) => {
			const region = form.parentElement;
			return {
				resultBottom: region.querySelector('[role="status"], [role="alert"]').getBoundingClientRect().bottom,
				buttonTop: region.querySelector('button[form="identity-form"]').getBoundingClientRect().top
			};
		});
		assert.ok(position.resultBottom <= position.buttonTop, "save feedback must be above the save button");
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

async function launchBrowser() {
	if (process.env.UI_BROWSER_URL) {
		const browser = await puppeteer.connect({ browserURL: process.env.UI_BROWSER_URL });
		const pages = await browser.pages();
		const page = pages.find((candidate) => candidate.url().startsWith("http://127.0.0.1:4173")) ?? pages[0];
		if (!page) throw new Error("UI_BROWSER_URL has no reusable page");
		return { browser, page, userDataDir: "", shared: true };
	}
	const userDataDir = mkdtempSync(join(tmpdir(), "sms-ui-browser-"));
	try {
		const browser = await puppeteer.launch({
			headless: true,
			executablePath: browserExecutable,
			args: [
				"--no-sandbox",
				"--disable-setuid-sandbox",
				"--disable-gpu",
				"--disable-dev-shm-usage",
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-background-networking",
				"--disable-component-update",
				`--user-data-dir=${userDataDir}`
			]
		});
		return { browser, page: await browser.newPage(), userDataDir, shared: false };
	} catch (error) {
		rmSync(userDataDir, { recursive: true, force: true });
		throw error;
	}
}

function listen(app) {
	return new Promise((resolve, reject) => {
		const server = app.listen(0, "127.0.0.1");
		server.once("listening", () => resolve(server));
		server.once("error", reject);
	});
}

async function closeServer(server) {
	server.closeAllConnections?.();
	await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
}

async function closeBrowser(browser, shared) {
	if (!browser) return;
	if (shared) {
		browser.disconnect();
		return;
	}
	const child = browser.process();
	browser.disconnect();
	if (!child || child.exitCode !== null || child.signalCode !== null) return;
	await new Promise((resolveClose) => {
		child.once("exit", resolveClose);
		child.kill("SIGKILL");
	});
}

async function waitForRoute(page, hash) {
	const subpage = hash.startsWith("#device/") ? hash.slice("#device/".length) : "";
	await page.waitForFunction(({ expectedHash, expectedSubpage }) => {
		if (location.hash !== expectedHash) return false;
		if (!expectedSubpage) return !document.querySelector("[data-device-subpage]");
		return document.querySelector(`[data-device-subpage="${expectedSubpage}"]`) !== null;
	}, { timeout: 15000 }, { expectedHash: hash, expectedSubpage: subpage });
}

async function openRoute(page, baseUrl, hash, expectedHash = hash) {
	const requestedHash = hash === "#overview" ? "" : hash;
	await page.goto(`${baseUrl}/${requestedHash}`, { waitUntil: "domcontentloaded" });
	await waitForRoute(page, expectedHash);
}

async function waitForAccordionContent(page, selector) {
	await page.waitForSelector(selector);
	// Presence precedes the accordion's final layout; coordinates sampled during expansion can miss.
	await page.waitForFunction(async (targetSelector) => {
		const target = document.querySelector(targetSelector);
		if (!target) return false;
		const moving = () => document.getAnimations().some((animation) =>
			animation.effect?.target instanceof Element && animation.effect.target.contains(target) &&
			(animation.pending || animation.playState === "running" || animation.playState === "paused"));
		if (moving()) return false;
		const before = target.getBoundingClientRect();
		await new Promise(requestAnimationFrame);
		const after = target.getBoundingClientRect();
		return !moving() && before.width > 0 && before.height > 0 &&
			["x", "y", "width", "height"].every((key) => before[key] === after[key]);
	}, { timeout: 1000 }, selector);
}

async function currentSubpage(page, hash) {
	return page.evaluate((expectedHash) => {
		const target = document.getElementById(expectedHash.slice(1));
		const header = document.querySelector(".app-header");
		const heading = document.querySelector("#device-subpage-title");
		const current = [...document.querySelectorAll("[data-device-subpage]")];
		const visible = (node) => {
			const style = getComputedStyle(node);
			return style.display !== "none" && style.visibility !== "hidden" && !node.closest("[hidden]");
		};
		return {
			hash: location.hash,
			targetIsCurrentPage: Boolean(target?.matches(".device-page")),
			targetVisible: Boolean(target && visible(target)),
			hiddenFragmentAnchors: document.querySelectorAll(".sr-only span[id^=device\\/]").length,
			currentCount: current.length,
			currentSubpage: current[0]?.getAttribute("data-device-subpage") ?? "",
			historyGroupCount: document.querySelectorAll('[data-tool-group="history"]').length,
			headingTop: heading?.getBoundingClientRect().top ?? -1,
			headerBottom: header?.getBoundingClientRect().bottom ?? -1,
			scrollWidth: document.documentElement.scrollWidth,
			innerWidth: window.innerWidth
		};
	}, hash);
}

function assertCurrentPage(state, hash) {
	assert.equal(state.hash, hash);
	assert.equal(state.targetIsCurrentPage, true, `${hash} must target the mounted page wrapper`);
	assert.equal(state.targetVisible, true, `${hash} target must be visible`);
	assert.equal(state.hiddenFragmentAnchors, 0, "route fragments must not use hidden anchors");
	assert.equal(state.currentCount, 1, "only the current device subpage may be rendered");
	assert.equal(state.currentSubpage, hash.slice("#device/".length));
	assert.equal(state.historyGroupCount, hash === "#device/diagnostics" ? 1 : 0,
		"diagnostic history must stay independent from the other subpages");
	assert.ok(state.headingTop >= state.headerBottom - 1, `${hash} heading is covered by the sticky header`);
}

async function clickDesktopRoute(page, subpage) {
	await page.click(`.desktop-sidebar a.device-subnav-link[href="#device/${subpage}"]`);
	await waitForRoute(page, `#device/${subpage}`);
}

async function domAriaAudit(page) {
	return page.evaluate(() => {
		const visible = (node) => {
			const style = getComputedStyle(node);
			return style.display !== "none" && style.visibility !== "hidden" && !node.closest("[hidden]");
		};
		const accessibleName = (node) => {
			const labelledBy = node.getAttribute("aria-labelledby");
			const associatedLabel = node.id ? document.querySelector(`label[for="${CSS.escape(node.id)}"]`) : null;
			return (node.getAttribute("aria-label") || labelledBy && document.getElementById(labelledBy)?.textContent ||
				associatedLabel?.textContent || node.closest("label")?.textContent || node.textContent || "").trim();
		};
		const ids = [...document.querySelectorAll("[id]")].map((node) => node.id);
		const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
		const unnamedControls = [...document.querySelectorAll("a,button,input,select,textarea")]
			.filter(visible).filter((node) => !accessibleName(node));
		const visibleNavCurrentCounts = [...document.querySelectorAll("nav")].filter(visible).map((nav) =>
			[...nav.querySelectorAll("a[aria-current]")].filter((link) => visible(link) && link.closest("nav") === nav).length);
		const headings = [...document.querySelectorAll("main h1,main h2,main h3,main h4")].filter(visible);
		const headingLevels = headings.map((node) => Number(node.tagName.slice(1)));
		const headingJumps = headingLevels.slice(1).filter((level, index) => level > headingLevels[index] + 1);
		return {
			duplicateIds,
			unnamedControls: unnamedControls.map((node) => node.outerHTML.slice(0, 120)),
			visibleNavCurrentCounts,
			headingJumps,
			nestedHeadersWithAria: [...document.querySelectorAll("main header[aria-labelledby]")].length,
			namedDeviceHeaderSections: [...document.querySelectorAll("main section.device-subpage-header[aria-label]")]
				.filter(visible).length
		};
	});
}

test("device subpages keep deep links, scroll position, controls, and accessible navigation in a real browser", { skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	const baseUrl = `http://127.0.0.1:${server.address().port}`;
	let browser;
	let page;
	let userDataDir;
	let shared = false;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 1280, height: 768 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "zh-TW"));
		const darkThemeScript = await page.evaluateOnNewDocument(() => localStorage.setItem("theme", "dark"));

		await openRoute(page, baseUrl, "#overview");
		assert.equal((await currentSubpage(page, "#overview")).hash, "#overview");
		await openRoute(page, baseUrl, "#device/not-a-real-page", "#device/connection");
		assertCurrentPage(await currentSubpage(page, "#device/connection"), "#device/connection");
		for (const subpage of ROUTES) {
			await openRoute(page, baseUrl, `#device/${subpage}`);
			assertCurrentPage(await currentSubpage(page, `#device/${subpage}`), `#device/${subpage}`);
		}

		await openRoute(page, baseUrl, "#device/connection");
		for (const subpage of ROUTES.slice(1)) {
			await page.evaluate(() => window.scrollTo(0, 320));
			await clickDesktopRoute(page, subpage);
			assertCurrentPage(await currentSubpage(page, `#device/${subpage}`), `#device/${subpage}`);
		}
		for (const subpage of ROUTES.slice(0, -1).reverse()) {
			await page.evaluate(() => history.back());
			await waitForRoute(page, `#device/${subpage}`);
			assertCurrentPage(await currentSubpage(page, `#device/${subpage}`), `#device/${subpage}`);
		}
		for (const subpage of ROUTES.slice(1)) {
			await page.evaluate(() => history.forward());
			await waitForRoute(page, `#device/${subpage}`);
			assertCurrentPage(await currentSubpage(page, `#device/${subpage}`), `#device/${subpage}`);
		}

		const activeStyle = await page.$eval(".desktop-sidebar .device-subnav-link[data-active=true]", (node) => {
			const color = getComputedStyle(node).backgroundColor;
			const canvas = document.createElement("canvas");
			canvas.width = 1;
			canvas.height = 1;
			const context = canvas.getContext("2d");
			if (!context) return { chroma: Number.NaN, dark: document.documentElement.classList.contains("dark") };
			context.fillStyle = color;
			context.fillRect(0, 0, 1, 1);
			const [red, green, blue] = context.getImageData(0, 0, 1, 1).data;
			return { color, chroma: Math.max(red, green, blue) - Math.min(red, green, blue), dark: document.documentElement.classList.contains("dark") };
		});
		assert.equal(activeStyle.dark, true);
		// Canvas rounds neutral OKLCH to 8-bit RGB with up to one level of channel difference.
		const neutralChroma = (chroma) => Number.isFinite(chroma) && chroma <= 1;
		assert.equal(neutralChroma(30), false, "a visibly tinted control must still fail");
		assert.ok(neutralChroma(activeStyle.chroma), `dark active subnav must stay neutral: ${JSON.stringify(activeStyle)}`);

		await page.focus(".desktop-sidebar .device-subnav-link");
		await page.keyboard.press("Tab");
		const desktopFocus = await page.evaluate(() => {
			const node = document.activeElement;
			const style = node ? getComputedStyle(node) : null;
			return {
				visible: node?.matches(".desktop-sidebar .device-subnav-link:focus-visible") ?? false,
				outlineWidth: style?.outlineWidth,
				outlineStyle: style?.outlineStyle,
				outlineOffset: style?.outlineOffset
			};
		});
		assert.equal(desktopFocus.visible, true);
		assert.equal(desktopFocus.outlineWidth, "2px");
		assert.notEqual(desktopFocus.outlineStyle, "none");
		assert.equal(desktopFocus.outlineOffset, "2px");

		await page.setViewport({ width: 390, height: 844 });
		await page.removeScriptToEvaluateOnNewDocument(darkThemeScript.identifier ?? darkThemeScript);
		await page.evaluate(() => localStorage.setItem("theme", "light"));
		await openRoute(page, baseUrl, "#device/connection");
		await page.reload({ waitUntil: "domcontentloaded" });
		await waitForRoute(page, "#device/connection");
		await page.waitForFunction(() => !document.documentElement.classList.contains("dark"));
		const lightActiveStyle = await page.$eval(".desktop-sidebar .device-subnav-link[data-active=true]", (node) => ({
			dark: document.documentElement.classList.contains("dark"),
			background: getComputedStyle(node).backgroundColor
		}));
		assert.equal(lightActiveStyle.dark, false);
		assert.match(lightActiveStyle.background, /oklch\([^)]*\s0(?:\s|\))/,
			"light active subnav must use the neutral palette");
		for (const subpage of ROUTES) {
			await openRoute(page, baseUrl, `#device/${subpage}`);
			const state = await currentSubpage(page, `#device/${subpage}`);
			assertCurrentPage(state, `#device/${subpage}`);
			assert.ok(state.scrollWidth <= state.innerWidth, `${subpage} overflows at 390px`);
		}
		await openRoute(page, baseUrl, "#device/connection");
		await page.click(".device-subpage-menu summary");
		await page.click('.device-subpage-menu-link[href="#device/diagnostics"]');
		await waitForRoute(page, "#device/diagnostics");
		assertCurrentPage(await currentSubpage(page, "#device/diagnostics"), "#device/diagnostics");
		await page.focus('.device-subpage-menu-link[href="#device/connection"]');
		await page.keyboard.press("Tab");
		const mobileFocus = await page.evaluate(() => {
			const node = document.activeElement;
			const style = node ? getComputedStyle(node) : null;
			return {
				visible: node?.matches('.device-subpage-menu-link[href="#device/diagnostics"]:focus-visible') ?? false,
				outlineWidth: style?.outlineWidth,
				outlineStyle: style?.outlineStyle,
				outlineOffset: style?.outlineOffset
			};
		});
		assert.equal(mobileFocus.visible, true);
		assert.equal(mobileFocus.outlineWidth, "2px");
		assert.notEqual(mobileFocus.outlineStyle, "none");
		assert.equal(mobileFocus.outlineOffset, "2px");

		await page.click("#mobile-nav-trigger");
		await page.waitForSelector("dialog.mobile-nav-dialog[open]");
		await page.keyboard.press("Escape");
		await page.waitForFunction(() => {
			const dialog = document.querySelector("dialog.mobile-nav-dialog");
			return !dialog?.open && document.activeElement?.id === "mobile-nav-trigger";
		});
		assert.equal(await page.evaluate(() => document.activeElement?.id), "mobile-nav-trigger");

		const audit = await domAriaAudit(page);
		assert.deepEqual(audit.duplicateIds, []);
		assert.deepEqual(audit.unnamedControls, []);
		assert.ok(audit.visibleNavCurrentCounts.every((count) => count <= 1));
		assert.deepEqual(audit.headingJumps, []);
		assert.equal(audit.nestedHeadersWithAria, 0);
		assert.equal(audit.namedDeviceHeaderSections, 1);
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		await closeServer(server);
	}
});

test("maintenance file inputs and actions reset when leaving the subpage", { skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
	const server = await listen(createApp({ webRoot: WEB_ROOT, openApiPath: OPENAPI_PATH, authRequired: false }));
	const baseUrl = `http://127.0.0.1:${server.address().port}`;
	const fixtureRoot = mkdtempSync(join(tmpdir(), "sms-ui-files-"));
	const restorePath = join(fixtureRoot, "restore.smscfg");
	const otaPath = join(fixtureRoot, "update.smsota");
	writeFileSync(restorePath, "harmless restore fixture");
	writeFileSync(otaPath, "harmless OTA fixture");
	let browser;
	let page;
	let userDataDir;
	let shared = false;
	try {
		({ browser, page, userDataDir, shared } = await launchBrowser());
		await page.setViewport({ width: 1280, height: 768 });
		await page.evaluateOnNewDocument(() => localStorage.setItem("locale", "zh-TW"));
		const attemptedHandlers = [];
		page.on("request", (request) => {
			if (/\/api\/(?:config\/restore\/start|ota\/start)/.test(request.url())) attemptedHandlers.push(request.url());
		});
		await openRoute(page, baseUrl, "#device/maintenance");
		await (await page.$("#restore-file")).uploadFile(restorePath);
		await (await page.$("#ota-file")).uploadFile(otaPath);
		await page.waitForFunction(() => document.querySelector("#restore-file")?.files.length === 1 && document.querySelector("#ota-file")?.files.length === 1);
		await page.click('.desktop-sidebar a.device-subnav-link[href="#device/connection"]');
		await waitForRoute(page, "#device/connection");
		await page.click('.desktop-sidebar a.device-subnav-link[href="#device/maintenance"]');
		await waitForRoute(page, "#device/maintenance");
		const state = await page.evaluate(() => ({
			restoreFiles: document.querySelector("#restore-file")?.files.length,
			otaFiles: document.querySelector("#ota-file")?.files.length,
			restoreDisabled: document.querySelector('[data-device-action="maintenance-restore"]')?.disabled,
			otaDisabled: document.querySelector('[data-device-action="maintenance-ota"]')?.disabled
		}));
		assert.deepEqual(state, { restoreFiles: 0, otaFiles: 0, restoreDisabled: true, otaDisabled: true });
		assert.deepEqual(attemptedHandlers, []);
	} finally {
		await closeBrowser(browser, shared);
		if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
		rmSync(fixtureRoot, { recursive: true, force: true });
		await closeServer(server);
	}
});
