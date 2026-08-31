import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import process from "node:process";
import test from "node:test";

const pageSource = await readFile(new URL("../src/routes/+page.svelte", import.meta.url), "utf8");
const apiSource = await readFile(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const layoutSource = await readFile(new URL("../src/routes/layout.css", import.meta.url), "utf8");
const localeSources = await Promise.all(["zh-TW", "zh-CN", "en"].map(async (locale) => [
	locale,
	JSON.parse(await readFile(new URL(`../src/lib/locales/${locale}.json`, import.meta.url), "utf8"))
]));

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

test("push provider fields expose only the fields used by each transport", async () => {
	const { pushProviderKeyFields } = await import("../src/lib/push-template-defaults.js");
	const expected = new Map([
		[1, []], [2, []], [3, []], [4, ["key1"]], [5, ["key1", "key2"]], [6, ["key1"]],
		[7, []], [8, ["key1"]], [9, ["key1"]], [10, ["key1", "key2"]], [11, []], [12, []]
	]);
	for (const [type, fields] of expected) assert.deepEqual(pushProviderKeyFields(type), fields, `provider ${type}`);
	assert.match(pageSource, /pushProviderKeyFields\(channel\.type\)\.includes\("key1"\)/);
	assert.match(pageSource, /pushProviderKeyFields\(channel\.type\)\.includes\("key2"\)/);
	assert.doesNotMatch(pageSource, /providerParam[12]/);
});

test("provider drafts preserve unsaved fields when switching away and back", async () => {
	const { switchProviderDraft } = await import("../src/lib/push-template-defaults.js");
	assert.equal(typeof switchProviderDraft, "function");
	const channel = {
		enabled: false, type: 10, name: "Channel 1",
		url: "https://example.invalid/telegram", urlSet: false,
		key1: "chat-id-draft", key1Set: false,
		key2: "bot-token-draft", key2Set: false,
		customBody: "", customBodySet: false,
		titleTemplate: "title draft", bodyTemplate: "body draft"
	};
	const drafts = {};
	switchProviderDraft(channel, drafts, 10, 7, "default title", "default body");
	channel.customBody = '{"message":"{message}"}';
	switchProviderDraft(channel, drafts, 7, 10, "default title", "default body");
	assert.deepEqual(
		{ url: channel.url, key1: channel.key1, key2: channel.key2 },
		{ url: "https://example.invalid/telegram", key1: "chat-id-draft", key2: "bot-token-draft" }
	);
	switchProviderDraft(channel, drafts, 10, 7, "default title", "default body");
	assert.equal(channel.customBody, '{"message":"{message}"}');
});

test("dark sidebar selection uses neutral semantic tokens", () => {
	const darkVars = layoutSource.match(/\.dark\s*\{([\s\S]*?)\n\}/)?.[1] ?? "";
	assert.match(darkVars, /--sidebar-primary:\s*oklch\([^;]*\s0\)/);
	assert.doesNotMatch(darkVars, /264\.376/);
	assert.match(layoutSource, /\.sidebar-link\[data-active="true"\]\s*\{[\s\S]*background:\s*var\(--sidebar-(?:primary|accent)\)/);
});

test("forwarding-rule tips use the accessible Dialog primitive and document parser behavior", () => {
	assert.match(pageSource, /import \{ Dialog \} from "bits-ui"/);
	assert.match(pageSource, /<Dialog\.Trigger[\s\S]*t\("forwardRulesTips"\)/);
	assert.match(pageSource, /<Dialog\.Overlay/);
	assert.match(pageSource, /<Dialog\.Content/);
	assert.match(pageSource, /<Dialog\.Title/);
	assert.match(pageSource, /<Dialog\.Description/);
	assert.match(pageSource, /<Dialog\.Close/);
	for (const [locale, messages] of localeSources) {
		for (const key of [
			"forwardRulesTips", "forwardRulesDialogTitle", "forwardRulesDialogDescription",
			"forwardRulesSyntax", "forwardRulesActions", "forwardRulesPrecedence",
			"forwardRulesEmpty", "forwardRulesEscaping", "forwardRulesExample1", "forwardRulesExample2"
		]) assert.equal(typeof messages[key], "string", `${locale}.${key}`);
		assert.match(messages.forwardRulesSyntax, /kw/);
		assert.match(messages.forwardRulesSyntax, /from/);
		assert.match(messages.forwardRulesSyntax, /re/);
		assert.match(messages.forwardRulesActions, /drop/);
		assert.match(messages.forwardRulesActions, /email/);
		assert.match(messages.forwardRulesActions, /1/);
		assert.match(messages.forwardRulesPrecedence, /first|第一|首|第一個|最先/i);
		assert.match(messages.forwardRulesEmpty, /0/);
		assert.match(messages.forwardRulesEscaping, /\\d/);
		assert.match(messages.forwardRulesExample1, /email,1/);
		assert.match(messages.forwardRulesExample2, /↹2$/);
		assert.doesNotMatch(`${messages.forwardRulesExample1}\n${messages.forwardRulesExample2}`, /push[12]/i);
	}
});

test("device tools are grouped without changing their existing route contracts", () => {
	assert.match(pageSource, /data-tool-group="connection"/);
	assert.match(pageSource, /data-tool-group="diagnostics"/);
	assert.match(pageSource, /data-tool-group="danger"/);
	assert.match(pageSource, /data-tool-group="maintenance"/);
	assert.match(pageSource, /t\("deviceGroupDangerDescription"\)/);
	for (const route of [
		"/query?type=ati", "/query?type=signal", "/query?type=siminfo", "/modem?action=hardreset",
		"/at?cmd="
	]) assert.match(pageSource, new RegExp(route.replace(/[?]/g, "\\?")));
	assert.match(apiSource, /`\/log\?\$\{query\}`/);
});

test("user-facing copy omits internal opaque-handle and modem implementation wording", () => {
	assert.doesNotMatch(pageSource, /esimProfilesDescription/);
	for (const [locale, messages] of localeSources) {
		assert.doesNotMatch(JSON.stringify(messages), /opaque|控制代碼|控制句柄/i, locale);
		for (const key of ["cellularCaNotReady", "cellularCaProvision", "networkModeHint", "networkModeWarningDescription"])
			assert.doesNotMatch(messages[key], /fail-closed|fails closed|ML307Y|provisioning|provision/i, `${locale}.${key}`);
		assert.match(messages.networkModeWarningDescription, /GET|ntfy/i);
	}
});

test("device workspace uses four canonical deep-link subpages with safe fallback", async () => {
	const navigation = await import("../src/lib/device-navigation.js");
	assert.deepEqual(navigation.parseDeviceHash(""), {
		mainTab: "overview", deviceSubpage: "connection", canonicalHash: "#overview"
	});
	assert.deepEqual(navigation.parseDeviceHash("device"), {
		mainTab: "device", deviceSubpage: "connection", canonicalHash: "#device/connection"
	});
	assert.deepEqual(navigation.parseDeviceHash("device/diagnostics"), {
		mainTab: "device", deviceSubpage: "diagnostics", canonicalHash: "#device/diagnostics"
	});
	assert.deepEqual(navigation.parseDeviceHash("device/not-a-page"), {
		mainTab: "device", deviceSubpage: "connection", canonicalHash: "#device/connection"
	});
	assert.equal(navigation.routeForMainTab("device"), "#device/connection");
	assert.deepEqual(navigation.DEVICE_SUBPAGES.map(({ value }) => value), ["connection", "diagnostics", "maintenance", "advanced"]);
	assert.match(pageSource, /addEventListener\("popstate"/);
	assert.match(pageSource, /history\.replaceState/);
});

test("device tool inventory appears exactly once across the subpages", async () => {
	const { DEVICE_TOOL_INVENTORY } = await import("../src/lib/device-navigation.js");
	const ids = Object.values(DEVICE_TOOL_INVENTORY).flat();
	assert.equal(new Set(ids).size, ids.length);
	for (const id of ids) assert.equal(pageSource.match(new RegExp(`data-device-action="${id}"`, "g"))?.length ?? 0, 1, id);
	for (const subpage of ["connection", "diagnostics", "maintenance", "advanced"])
		assert.match(pageSource, new RegExp(`data-device-subpage="${subpage}"`));
});

test("device navigation keeps group labels and children on the shared readable scale", () => {
	assert.match(pageSource, /class="device-tool-group-heading"[\s\S]*<h2/);
	assert.match(pageSource, /class="device-subpage-menu(?:[" ])/);
	assert.match(layoutSource, /\.sidebar-group-label[\s\S]*font-size:\s*0\.875rem/);
	assert.match(layoutSource, /\.device-tool-group-heading h2[\s\S]*font-size:\s*0\.875rem/);
	assert.match(layoutSource, /\.device-tool-group \[data-slot="accordion-trigger"\][\s\S]*font-size:\s*0\.875rem/);
	assert.match(layoutSource, /\.device-subnav[\s\S]*padding-left/);
	assert.match(layoutSource, /\.device-subpage-menu[\s\S]*overflow-x:\s*hidden/);
	assert.match(layoutSource, /\.device-tool-group-danger::before[\s\S]*width:\s*2px/);
});
