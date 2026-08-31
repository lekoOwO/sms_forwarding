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
	}, { timeout: 5000 }, { expectedHash: hash, expectedSubpage: subpage });
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
			const oklch = color.match(/oklch\([^ ]+\s+([^ ]+)\s+[^)]+\)/);
			const rgb = color.match(/\d+/g)?.map(Number) ?? [];
			return { chroma: oklch ? Number(oklch[1]) : rgb.length >= 3 ? Math.max(...rgb.slice(0, 3)) - Math.min(...rgb.slice(0, 3)) : Number.NaN, dark: document.documentElement.classList.contains("dark") };
		});
		assert.equal(activeStyle.dark, true);
		assert.ok(activeStyle.chroma < 0.01, "dark active subnav must stay neutral");

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

		await page.click('button[aria-label="Open navigation"]');
		await page.waitForSelector("dialog.mobile-nav-dialog[open]");
		await page.keyboard.press("Escape");
		await page.waitForFunction(() => !document.querySelector("dialog.mobile-nav-dialog")?.open);
		assert.equal(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")), "Open navigation");

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
