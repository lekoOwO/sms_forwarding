import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import puppeteer from "puppeteer-core";
import { createApp } from "../server.mjs";

const ROOT = resolve(new URL("../..", import.meta.url).pathname);
const WEB_ROOT = join(ROOT, "web", "build");
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
		await page.waitForSelector("#forward-rules");
		let saves = 0;
		page.on("request", (request) => { if (new URL(request.url()).pathname === "/save") saves++; });
		await page.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "Add rule").click());
		await page.type("#rule-pattern-0", 'a,"b"');
		await page.$eval("#rule-actions-0", (input) => { input.value = "email,2"; input.dispatchEvent(new Event("input", { bubbles: true })); });
		assert.equal(await page.$eval("#forward-rules", (input) => input.value), 'kw,"a,""b""","email,2",1');
		await page.type("#rule-test-sender", "+123456");
		await page.type("#rule-test-message", 'a,"b"');
		await page.click("#rule-test");
		await page.waitForSelector("#rule-preview-result");
		assert.match(await page.$eval("#rule-preview-result", (region) => region.textContent), /First match: line 1/);
		assert.match(await page.$eval("#rule-preview-result", (region) => region.textContent), /email, 2/);
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

// The journey includes cold Chromium and application startup; probe response still has a 5 s deadline.
test("mobile keepalive settings preserve the HTTP draft and use a dedicated certificate target", { timeout: 45000, skip: !browserAvailable ? "No local Chromium-compatible executable" : false }, async () => {
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
		assert.match(await page.$eval("#keepalive-url", (input) => input.closest("form").textContent), /HTTPS is required/);
		assert.equal(await page.$eval("#keepalive-enabled", (input) => input.getAttribute("aria-checked")), "false");
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
		await page.$eval('[data-device-action="diagnostics-network"]', (button) => { const panel = button.closest('[data-slot="accordion-content"]'); if (panel) document.querySelector(`[aria-controls="${panel.id}"]`)?.click(); });
		await page.$eval('[data-device-action="diagnostics-network"]', (button) => button.click());
		await page.waitForSelector('summary[title="registration: 5"]');
		assert.match(await page.$eval('summary[title="registration: 5"]', (summary) => summary.textContent), /Registered on a roaming network/);
		assert.match(await page.$eval('summary[title*="cesq"]', (summary) => summary.textContent), /CSQ: ≥ −51 dBm/);
		await page.focus('summary[title="registration: 5"]');
		await page.keyboard.press("Enter");
		assert.equal(await page.$eval('summary[title="registration: 5"]', (summary) => summary.parentElement.open), true);
		await page.setViewport({ width: 390, height: 844 });
		await page.tap('summary[title="registration: 5"]');
		assert.equal(await page.$eval('summary[title="registration: 5"]', (summary) => summary.parentElement.open), false);
		await page.tap('summary[title="registration: 5"]');
		assert.match(await page.$eval('summary[title="registration: 5"]', (summary) => summary.nextElementSibling.textContent), /registration: 5/);
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
