import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, pbkdf2Sync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { connect } from "node:net";
import test from "node:test";
import { createApp, serializePushTestStatus } from "../server.mjs";

const auth = `Basic ${Buffer.from("admin:admin123").toString("base64")}`;
const headers = { Authorization: auth, "X-CSRF-Token": "mock-csrf-token" };

test("rule preview requires authorization, validates fields, and leaves saved rules unchanged", async () => {
	await withServer(async (baseUrl) => {
		const before = (await (await request(baseUrl, "/api/config")).json()).config.forwardRules;
		const values = { rules: '#!forward-rules-csv-v1\nkw,"a,b","email,2"', sender: "+1234", text: "a,b" };
		assert.equal((await fetch(`${baseUrl}/api/rules/preview`, { method: "POST", body: new URLSearchParams(values) })).status, 401);
		assert.equal((await request(baseUrl, "/api/rules/preview", { method: "POST", headers: { "X-CSRF-Token": "wrong" }, body: new URLSearchParams(values) })).status, 403);
		const preview = await completed(baseUrl, await form(baseUrl, "/api/rules/preview", values));
		assert.equal(preview.success, true);
		assert.deepEqual(preview.data, { matched: true, line: 1, drop: false, email: true, channelMask: 2, previewEngine: "mock" });
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, before);
		for (const invalid of [{ ...values, sender: "a".repeat(33) }, { ...values, text: "a".repeat(2049) }, { ...values, extra: "no" }]) {
			assert.equal((await form(baseUrl, "/api/rules/preview", invalid)).status, 400);
		}
		const rejected = await completed(baseUrl, await form(baseUrl, "/save", { forwardRules: '#!forward-rules-csv-v1\nkw,"broken,email' }));
		assert.equal(rejected.code, "ACTION_CONFIG_INVALID");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, before);
	});
});

async function withServer(run, options = {}) {
	const server = createApp(options).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	try { await run(`http://127.0.0.1:${server.address().port}`); }
	finally { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

function request(baseUrl, path, init = {}) {
	return fetch(`${baseUrl}${path}`, { ...init, headers: { ...headers, ...init.headers } });
}

function rawHttp(baseUrl, raw) {
	const { hostname, port } = new URL(baseUrl);
	return new Promise((resolve, reject) => {
		let response = "";
		const socket = connect(Number(port), hostname, () => socket.end(raw));
		socket.setEncoding("utf8");
		socket.on("data", (chunk) => response += chunk);
		socket.on("end", () => resolve(response));
		socket.on("error", reject);
	});
}

function form(baseUrl, path, values) {
	return request(baseUrl, path, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(values)
	});
}

async function completed(baseUrl, response) {
	const body = await response.json();
	if (response.status !== 202 || body.code !== "ACTION_JOB_ACCEPTED") return body;
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const job = await (await request(baseUrl, `/api/jobs?id=${body.data.jobId}`)).json();
		if (job.state === "succeeded" || job.state === "failed") return job.result;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	throw new Error("job timeout");
}

async function completedPushTest(baseUrl, channel, detail = false) {
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const status = await (await request(baseUrl, `/api/push/test?channel=${channel}${detail ? "&detail=1" : ""}`)).json();
		if (status.done) return status;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	throw new Error("push test timeout");
}

test("push test serializer exposes parse detail only for terminal opt-in responses", () => {
	const terminal = {
		queued: false, running: false, done: true, success: false, message: "Malformed response",
		failureReason: "response_invalid", failureParseReason: "field_count",
		cleanupReason: "response_invalid", cleanupParseReason: "quote",
		failureParseShape: { fieldCount: 5, quoteMask: 16, presenceMask: 1,
			stateClass: "unknown", lineClass: "none", singleFieldClass: "none" },
		cleanupParseShape: { fieldCount: 0, quoteMask: 0, presenceMask: 4,
			stateClass: "none", lineClass: "missing", singleFieldClass: "none" }
	};
	assert.deepEqual(serializePushTestStatus(terminal, true), terminal);
	const readData = {
		...terminal,
		failureParseReason: "read_data",
		failureParseShape: { fieldCount: 4, quoteMask: 0, presenceMask: 16,
			stateClass: "none", lineClass: "none", singleFieldClass: "none" }
	};
	assert.deepEqual(serializePushTestStatus(readData, true), readData);
	const singleField = {
		...terminal,
		failureParseShape: { fieldCount: 1, quoteMask: 0, presenceMask: 4,
			stateClass: "none", lineClass: "none", singleFieldClass: "zero" }
	};
	assert.deepEqual(serializePushTestStatus(singleField, true), singleField);
	const mismatchedSingleField = {
		...terminal,
		failureParseShape: { fieldCount: 5, quoteMask: 0, presenceMask: 1,
			stateClass: "unknown", lineClass: "none", singleFieldClass: "zero" }
	};
	assert.equal(Object.hasOwn(serializePushTestStatus(mismatchedSingleField, true),
		"failureParseShape"), false);
	assert.deepEqual(serializePushTestStatus(terminal), {
		queued: false, running: false, done: true, success: false, message: "Malformed response"
	});
	assert.deepEqual(serializePushTestStatus({ ...terminal, done: false }, true), {
		queued: false, running: false, done: false, success: false, message: "Malformed response"
	});
	const noShape = serializePushTestStatus({ ...terminal,
		failureParseReason: "none", cleanupParseReason: "none" }, true);
	assert.equal(Object.hasOwn(noShape, "failureParseShape"), false);
	assert.equal(Object.hasOwn(noShape, "cleanupParseShape"), false);
	const responseReason = {
		...terminal, transportPath: "cellular", dispatchAttempted: true, failureStage: "response",
		failureResponseReason: "http_parse"
	};
	assert.equal(serializePushTestStatus(responseReason, true).failureResponseReason, "http_parse");
	assert.equal(serializePushTestStatus({ ...responseReason,
		failureResponseReason: "modem_command" }, true).failureResponseReason, "modem_command");
	assert.equal(Object.hasOwn(serializePushTestStatus({ ...responseReason,
		failureStage: "http" }, true), "failureResponseReason"), false);
	assert.equal(Object.hasOwn(serializePushTestStatus({ ...responseReason,
		success: true }, true), "failureResponseReason"), false);
	assert.equal(Object.hasOwn(serializePushTestStatus({ ...responseReason,
		failureResponseReason: "not-a-reason" }, true), "failureResponseReason"), false);
	assert.equal(Object.hasOwn(serializePushTestStatus(responseReason, false), "failureResponseReason"), false);
});

function decrypt(bytes, passphrase) {
	const value = Buffer.from(bytes);
	assert.equal(value.subarray(0, 8).toString(), "SMSCFG01");
	assert.equal(value.readUInt16LE(8), 1);
	assert.equal(value[10], 1);
	assert.equal(value[11], 1);
	assert.equal(value.readUInt32LE(12), 210000);
	const decipher = createDecipheriv("aes-256-gcm",
		pbkdf2Sync(passphrase, value.subarray(16, 32), 210000, 32, "sha256"),
		value.subarray(32, 44));
	decipher.setAAD(value.subarray(0, 44));
	decipher.setAuthTag(value.subarray(-16));
	return Buffer.concat([decipher.update(value.subarray(44, -16)), decipher.final()]);
}

function encryptPlaintext(bytes, passphrase) {
	const salt = Buffer.from(Array.from({ length: 16 }, (_, index) => index));
	const iv = Buffer.from(Array.from({ length: 12 }, (_, index) => index + 16));
	const header = Buffer.alloc(44);
	header.write("SMSCFG01");
	header.writeUInt16LE(1, 8);
	header[10] = 1;
	header[11] = 1;
	header.writeUInt32LE(210000, 12);
	salt.copy(header, 16);
	iv.copy(header, 32);
	const cipher = createCipheriv("aes-256-gcm", pbkdf2Sync(passphrase, salt, 210000, 32, "sha256"), iv);
	cipher.setAAD(header);
	return Buffer.concat([header, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
}

async function assertAction(response, status, code) {
	assert.equal(response.status, status);
	const body = await response.json();
	assert.equal(body.code, code);
	assert.deepEqual(Object.keys(body).sort(), ["code", "data", "detail", "success"]);
	return body;
}

function crc32(bytes) {
	let crc = 0xffffffff;
	for (const byte of bytes) {
		crc ^= byte;
		for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

async function restore(baseUrl, bytes, passphrase) {
	const start = await form(baseUrl, "/api/config/restore/start", { size: bytes.length });
	assert.equal(start.status, 201);
	const id = (await start.json()).data.uploadId;
	assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${id}&offset=0`, {
		method: "POST", headers: { "Content-Type": "text/plain" }, body: Buffer.from(bytes).toString("base64")
	})).status, 200);
	return completed(baseUrl, await form(baseUrl, `/api/config/restore/finish?id=${id}`, { passphrase }));
}

test("auth, CSRF, AP-local exceptions, snapshot counts, and ping match the current API", async () => {
	await withServer(async (baseUrl) => {
		const unauthorized = await fetch(`${baseUrl}/api/config`);
		assert.equal(unauthorized.status, 401);
		assert.match(unauthorized.headers.get("www-authenticate"), /^Basic /);
		const snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.status.ip, "192.168.1.1");
		assert.equal(snapshot.config.kaTrafficKB, 1);
		assert.deepEqual([
			snapshot.config.webAccounts.length,
			snapshot.config.wifiProfiles.length,
			snapshot.config.pushChannels.length
		], [10, 5, 5]);
		const noCsrf = await fetch(`${baseUrl}/ping`, { method: "POST", headers: { Authorization: auth } });
		assert.equal(noCsrf.status, 403);
		assert.equal((await noCsrf.json()).code, "ACTION_CSRF_INVALID");
		assert.equal((await completed(baseUrl, await request(baseUrl, "/ping", { method: "POST" }))).code,
			"ACTION_PING_UNSUPPORTED");
	});
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/apstatus`)).status, 200);
		assert.equal((await fetch(`${baseUrl}/wifiscan`)).status, 200);
		assert.equal((await fetch(`${baseUrl}/api/config`)).status, 401);
		assert.equal((await fetch(`${baseUrl}/wificonfig`, {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "ssid=Office&pass=wifi-secret"
		})).status, 403);
		const saved = await fetch(`${baseUrl}/wificonfig`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", "X-SMS-CSRF": "1" },
			body: "ssid=Office&pass=wifi-secret"
		});
		assert.equal((await saved.json()).success, true);
	}, { apLocalAddress: "127.0.0.1" });
});

test("masked secrets retain blank same-type values and clear them on provider changes", async () => {
	await withServer(async (baseUrl) => {
		for (const values of [
			{ smtpServer: "smtp.example.com", smtpPort: 465, smtpUser: "sender@example.com", smtpPass: "smtp-secret", smtpSendTo: "ops@example.com" },
			{ account0user: "admin", account0pass: "" },
			{ wifi0ssid: "Office", wifi0pass: "wifi-secret" },
			{ push0en: "on", push0type: 9, push0name: "Gotify", push0url: "https://gotify.example/message", push0key1: "push-secret", push0key2: "", push0body: "", push0title: "{sender}", push0template: "{message}" }
		]) assert.equal((await completed(baseUrl, await form(baseUrl, "/save", values))).code, "ACTION_CONFIG_SAVED");
		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.smtpPass, "");
		assert.equal(snapshot.config.webAccounts[0].password, "");
		assert.equal(snapshot.config.wifiProfiles[0].password, "");
		assert.deepEqual([snapshot.config.pushChannels[0].urlSet, snapshot.config.pushChannels[0].key1Set], [true, true]);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 9, push0name: "Renamed", push0url: "", push0key1: "",
			push0key2: "", push0body: "", push0title: "Updated", push0template: "{message}"
		}))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([snapshot.config.pushChannels[0].urlSet, snapshot.config.pushChannels[0].key1Set], [true, true]);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 10, push0name: "Telegram", push0title: "{sender}", push0template: "{message}"
		}))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.pushChannels[0].type,
			snapshot.config.pushChannels[0].urlSet,
			snapshot.config.pushChannels[0].key1Set
		], [10, false, false]);
	});
});

test("cellular overrides stay redacted and rejected CA candidates require a fresh per-channel probe", async () => {
	await withServer(async (baseUrl) => {
		let saved = await completed(baseUrl, await form(baseUrl, "/save", {
			push1en: "on", push1type: 9, push1name: "Cellular",
			push1url: "https://push.example/message", push1key1: "token",
			push1cellularEnabled: "1", push1cellularUrl: "https://cell.example/message",
			push1title: "{sender}", push1template: "{message}"
		}));
		assert.equal(saved.code, "ACTION_CONFIG_SAVED");
		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.pushChannels[1].cellularEnabled,
			snapshot.config.pushChannels[1].cellularUrlSet,
			snapshot.config.pushChannels[1].cellularUrl
		], [true, true, undefined]);

		saved = await completed(baseUrl, await form(baseUrl, "/save", {
			push1en: "on", push1type: 9, push1name: "Cellular",
			push1cellularEnabled: "0", push1cellularUrl: "",
			push1title: "{sender}", push1template: "{message}"
		}));
		assert.equal(saved.success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([snapshot.config.pushChannels[1].cellularEnabled, snapshot.config.pushChannels[1].cellularUrlSet], [false, true]);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push1cellularEnabled: "1", push1cellularUrlClear: "1"
		}))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.pushChannels[1].cellularUrlSet, false);
		assert.equal(snapshot.config.pushChannels[1].enabled, true, "cellular-only updates must preserve provider enablement");
		assert.equal(snapshot.config.pushChannels[1].type, 9);
		assert.equal(snapshot.config.pushChannels[1].name, "Cellular");
		assert.deepEqual([snapshot.config.pushChannels[1].urlSet, snapshot.config.pushChannels[1].key1Set], [true, true]);
		assert.deepEqual([snapshot.config.pushChannels[1].titleTemplate, snapshot.config.pushChannels[1].bodyTemplate], ["{sender}", "{message}"]);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { push1type: 9, push1name: "Disabled" }))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.pushChannels[1].enabled, false, "ordinary provider saves still disable when en is omitted");
	});
	await withServer(async (baseUrl) => {
		const initialStatus = await (await request(baseUrl, "/api/push/ca/status?channel=1")).json();
		assert.deepEqual(initialStatus.data, { configured: false, sha256: "" });
		const probe = await request(baseUrl, "/api/push/ca/probe?channel=1", { method: "POST" });
		assert.equal(probe.status, 202);
		const probeResult = await completed(baseUrl, probe);
		assert.equal(probeResult.code, "PUSH_CA_PROBE_READY");
		assert.deepEqual(Object.keys(probeResult.data).sort(), ["chain", "expiresInMs", "nonce"]);
		assert.equal(probeResult.data.chain.length > 0, true);
		assert.deepEqual(Object.keys(probeResult.data.chain[0]).sort(), ["aki", "certSha256", "issuerDer"]);
		assert.equal(probeResult.data.expiresInMs, 30000);
		assert.match(probeResult.data.chain[0].certSha256, /^[0-9a-f]{64}$/);
		assert.equal(typeof probeResult.data.chain[0].issuerDer, "string");
		assert.match(probeResult.data.chain[0].aki, /^(?:[0-9a-f]{2}){0,32}$/);
		assert.match(probeResult.data.nonce, /^[0-9a-f]{32}$/);
		let install = await request(baseUrl,
			`/api/push/ca/install?channel=1&nonce=${probeResult.data.nonce}`, {
				method: "POST", headers: { "Content-Type": "application/pkix-cert" }, body: Buffer.from([0x30, 0x01])
			});
		assert.equal(install.status, 202);
		assert.equal((await completed(baseUrl, install)).code, "PUSH_CA_REJECTED");
		install = await request(baseUrl, `/api/push/ca/install?channel=1&nonce=${probeResult.data.nonce}`, {
			method: "POST", headers: { "Content-Type": "application/pkix-cert" }, body: Buffer.from([0x30, 0x01])
		});
		assert.equal((await install.json()).code, "PUSH_CA_STALE");
		const reprobe = await completed(baseUrl, await request(baseUrl, "/api/push/ca/probe?channel=1", { method: "POST" }));
		install = await request(baseUrl, `/api/push/ca/install?channel=1&nonce=${reprobe.data.nonce}`, {
			method: "POST", headers: { "Content-Type": "application/pkix-cert" }, body: Buffer.from([0x30, 0x01])
		});
		assert.equal((await completed(baseUrl, install)).code, "PUSH_CA_INSTALLED");
		const ready = await (await request(baseUrl, "/api/push/ca/status?channel=1")).json();
		assert.equal(ready.data.configured, true);
		assert.match(ready.data.sha256, /^[0-9a-f]{64}$/);
	}, { pushCaRejectCount: 1 });
});

test("CA routes reject chunked bodies and unsupported methods with route-specific Allow headers", async () => {
	await withServer(async (baseUrl) => {
		for (const [path, allow] of [
			["/api/push/ca/status?channel=0", "GET"],
			["/api/push/ca/probe?channel=0", "POST"],
			["/api/push/ca/install?channel=0&nonce=00000000000000000000000000000000", "POST"]
		]) {
			const response = await request(baseUrl, path, { method: "PUT" });
			assert.equal(response.status, 405);
			assert.equal(response.headers.get("allow"), allow);
			assert.deepEqual(await response.json(), { success: false, code: "ACTION_INPUT_INVALID", data: {}, detail: "method" });
		}
		for (const [method, path, contentType] of [
			["GET", "/api/push/ca/status?channel=0", "application/x-www-form-urlencoded"],
			["POST", "/api/push/ca/probe?channel=0", "application/x-www-form-urlencoded"],
			["POST", "/api/push/ca/install?channel=0&nonce=00000000000000000000000000000000", "application/pkix-cert"]
		]) {
			const url = new URL(baseUrl);
			const response = await rawHttp(baseUrl,
				`${method} ${path} HTTP/1.1\r\nHost: ${url.host}\r\nAuthorization: ${auth}\r\nX-CSRF-Token: mock-csrf-token\r\nContent-Type: ${contentType}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n`);
			assert.match(response, /^HTTP\/1\.1 400 /);
			assert.match(response, /"code":"ACTION_INPUT_INVALID"/);
		}
	});
});

test("global notification switches round-trip independently without clearing channel state or secrets", async () => {
	await withServer(async (baseUrl) => {
		for (const values of [
			{ emailEnabled: "0", smtpServer: "smtp.example.com", smtpPort: 465, smtpUser: "sender@example.com", smtpPass: "smtp-secret", smtpSendTo: "ops@example.com" },
			{ pushEnabled: "0", push0en: "on", push0type: 9, push0name: "Gotify", push0url: "https://gotify.example/message", push0key1: "push-secret", push0title: "{sender}", push0template: "{message}" }
		]) assert.equal((await completed(baseUrl, await form(baseUrl, "/save", values))).code, "ACTION_CONFIG_SAVED");

		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([snapshot.config.emailEnabled, snapshot.config.pushEnabled], [false, false]);
		assert.equal(snapshot.config.smtpPass, "");
		assert.deepEqual([
			snapshot.config.pushChannels[0].url,
			snapshot.config.pushChannels[0].key1,
			snapshot.config.pushChannels[0].urlSet,
			snapshot.config.pushChannels[0].key1Set
		], ["", "", true, true]);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { emailEnabled: "1" }))).code,
			"ACTION_CONFIG_SAVED");
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.emailEnabled, true);
		assert.equal(snapshot.config.pushEnabled, false);
		assert.equal(snapshot.status.emailConfigured, true);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { pushEnabled: "1" }))).code,
			"ACTION_CONFIG_SAVED");
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.emailEnabled, true);
		assert.equal(snapshot.config.pushEnabled, true);
		assert.deepEqual([
			snapshot.config.pushChannels[0].enabled,
			snapshot.config.pushChannels[0].type,
			snapshot.config.pushChannels[0].name,
			snapshot.config.pushChannels[0].urlSet,
			snapshot.config.pushChannels[0].key1Set,
			snapshot.config.pushChannels[0].titleTemplate,
			snapshot.config.pushChannels[0].bodyTemplate
		], [true, 9, "Gotify", true, true, "{sender}", "{message}"]);

	});

	for (const [field, invalid] of [
			["emailEnabled", "+1"], ["emailEnabled", "01"], ["emailEnabled", " 1"],
			["pushEnabled", "+1"], ["pushEnabled", "01"], ["pushEnabled", "1 "]
	]) {
		await withServer(async (baseUrl) => {
			const unchanged = await (await request(baseUrl, "/api/config")).json();
			const sibling = field === "emailEnabled"
				? { smtpServer: "must-not-save.example" }
				: { push0en: "on", push0type: 9, push0name: "must-not-save" };
			const rejected = await completed(baseUrl, await form(baseUrl, "/save", { [field]: invalid, ...sibling }));
			assert.deepEqual([rejected.code, rejected.detail], ["ACTION_CONFIG_INVALID", field]);
			assert.deepEqual(await (await request(baseUrl, "/api/config")).json(), unchanged);
		});
	}
});

test("push channel tests require CSRF and keep bounded per-channel results independent", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/push/test?channel=0`)).status, 401);
		assert.equal((await fetch(`${baseUrl}/api/push/test?channel=0`, {
			method: "POST", headers: { Authorization: auth }
		})).status, 403);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push2en: "on", push2type: 9, push2name: "Incomplete",
			push2url: "https://push3.example/message"
		}))).success, true);
		const incomplete = await request(baseUrl, "/api/push/test?channel=2", { method: "POST" });
		assert.equal(incomplete.status, 409);
		assert.match((await incomplete.json()).message, /disabled or incomplete/);

		for (const [index, secret] of [[0, "first-secret"], [1, "second-secret"]]) {
			assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
				[`push${index}en`]: "on", [`push${index}type`]: 9,
				[`push${index}name`]: `Channel ${index + 1}`,
				[`push${index}url`]: `https://push${index + 1}.example/message`,
				[`push${index}key1`]: secret, [`push${index}title`]: "{sender}",
				[`push${index}template`]: "{message}"
			}))).code, "ACTION_CONFIG_SAVED");
		}

		const first = await request(baseUrl, "/api/push/test?channel=0", { method: "POST" });
		assert.equal(first.status, 202);
		const firstStatus = await first.json();
		assert.deepEqual(Object.keys(firstStatus).sort(), ["done", "message", "queued", "running", "success"]);
		assert.equal(firstStatus.queued, true);
		const ping = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(ping.status, 202);
		const exportDuringTest = await form(baseUrl, "/api/config/export", { passphrase: "short" });
		await assertAction(exportDuringTest, 409, "ACTION_BUSY");
		const duplicate = await request(baseUrl, "/api/push/test?channel=0", { method: "POST" });
		assert.equal(duplicate.status, 409);
		assert.equal((await duplicate.json()).queued, true);
		await assertAction(await form(baseUrl, "/save", { pushEnabled: "0" }), 409, "ACTION_BUSY");
		assert.equal((await (await request(baseUrl, "/api/push/test?channel=1")).json()).done, false);
		await completed(baseUrl, ping);

		assert.equal((await request(baseUrl, "/api/push/test?channel=1", { method: "POST" })).status, 202);
		const [firstDone, secondDone, untouched] = await Promise.all([
			completedPushTest(baseUrl, 0), completedPushTest(baseUrl, 1),
			request(baseUrl, "/api/push/test?channel=2").then((response) => response.json())
		]);
		assert.deepEqual([firstDone.done, firstDone.success, secondDone.done, secondDone.success],
			[true, true, true, true]);
		assert.deepEqual([untouched.done, untouched.success], [false, false]);
		assert.doesNotMatch(JSON.stringify([firstStatus, firstDone, secondDone, untouched]), /first-secret|second-secret/);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { networkMode: 1 }))).success, true);
		const unsupportedResponse = await request(baseUrl, "/api/push/test?channel=0", { method: "POST" });
		assert.equal(unsupportedResponse.status, 409);
		const unsupported = await unsupportedResponse.json();
		assert.deepEqual([unsupported.queued, unsupported.running, unsupported.done, unsupported.success],
			[false, false, true, false]);
		assert.match(unsupported.message, /Cellular push is not supported/);
	}, { jobDelayMs: 100 });
});

test("push test request ordering matches firmware and POST accepts no body", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/push/test?channel=0`, { method: "HEAD" })).status, 401);
		assert.equal((await fetch(`${baseUrl}/api/push/test?channel=0`, {
			method: "HEAD", headers: { Authorization: auth }
		})).status, 405);
		const unsupported = await fetch(`${baseUrl}/api/push/test?channel=0`, {
			method: "PUT", headers: { Authorization: auth }
		});
		assert.equal(unsupported.status, 405);
		assert.deepEqual(Object.keys(await unsupported.json()).sort(),
			["done", "message", "queued", "running", "success"]);
		assert.equal((await fetch(`${baseUrl}/api/push/test?channel=0`, {
			method: "POST", headers: { Authorization: auth }, body: "not-allowed"
		})).status, 403);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 1, push0name: "No body",
			push0url: "https://push.example/message"
		}))).success, true);
		const withBody = await request(baseUrl, "/api/push/test?channel=0", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "unexpected=1"
		});
		assert.equal(withBody.status, 400);
		assert.match((await withBody.json()).message, /body is not allowed/i);
	});
});

test("push test detail is strict, terminal-only, and additive", async () => {
	await withServer(async (baseUrl) => {
		for (const suffix of [
			"&detail=0", "&detail=2", "&detail=", "&detail=1&detail=1",
			"&&detail=1", "&detail=1&", "&unknown=1"
		]) {
			const response = await request(baseUrl, `/api/push/test?channel=0${suffix}`);
			assert.equal(response.status, 400);
			assert.deepEqual(Object.keys(await response.json()).sort(),
				["done", "message", "queued", "running", "success"]);
		}

		const legacy = await (await request(baseUrl, "/api/push/test?channel=0")).json();
		assert.deepEqual(Object.keys(legacy).sort(),
			["done", "message", "queued", "running", "success"]);
		const detail = await (await request(baseUrl, "/api/push/test?channel=0&detail=1")).json();
		assert.deepEqual(Object.keys(detail).sort(),
			["done", "message", "queued", "running", "success"]);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 1, push0name: "Detailed",
			push0url: "https://push.example/message"
		}))).success, true);
		const legacyPost = await request(baseUrl, "/api/push/test?channel=0", { method: "POST" });
		assert.equal(legacyPost.status, 202);
		const legacyPostBody = await legacyPost.json();
		assert.deepEqual(Object.keys(legacyPostBody).sort(),
			["done", "message", "queued", "running", "success"]);
		const queued = await request(baseUrl, "/api/push/test?channel=0&detail=1", { method: "POST" });
		assert.equal(queued.status, 202);
		const queuedBody = await queued.json();
		assert.deepEqual(Object.keys(queuedBody).sort(), [
			"dispatchAttempted", "done", "failureStage", "httpStatus", "message",
			"queued", "running", "success", "transportPath"
		]);
		assert.deepEqual([
			queuedBody.transportPath, queuedBody.dispatchAttempted,
			queuedBody.failureStage, queuedBody.httpStatus
		], ["wifi", true, "none", 204]);
		const terminal = await completedPushTest(baseUrl, 0, true);
		assert.deepEqual(Object.keys(terminal).sort(), [
			"dispatchAttempted", "done", "failureStage", "httpStatus", "message",
			"queued", "running", "success", "transportPath"
		]);
		assert.deepEqual([
			terminal.transportPath, terminal.dispatchAttempted, terminal.failureStage, terminal.httpStatus
		], ["wifi", true, "none", 204]);
	}, { jobDelayMs: 0 });
});

test("device restart is authenticated, POST-only, CSRF-protected, empty-body, and single-admission", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/device/restart`)).status, 401);
		const get = await request(baseUrl, "/api/device/restart");
		assert.equal(get.status, 405);
		assert.equal(get.headers.get("allow"), "POST");
		assert.equal((await fetch(`${baseUrl}/api/device/restart`, { method: "HEAD" })).status, 401);
		const head = await request(baseUrl, "/api/device/restart", { method: "HEAD" });
		assert.equal(head.status, 405);
		assert.equal(head.headers.get("allow"), "POST");
		const put = await request(baseUrl, "/api/device/restart", { method: "PUT" });
		assert.equal(put.status, 405);
		assert.equal(put.headers.get("allow"), "POST");

		const noCsrf = await fetch(`${baseUrl}/api/device/restart`, {
			method: "POST", headers: { Authorization: auth }
		});
		assert.equal(noCsrf.status, 403);
		assert.equal((await noCsrf.json()).code, "ACTION_CSRF_INVALID");
		const noCsrfWithBody = await fetch(`${baseUrl}/api/device/restart`, {
			method: "POST", headers: { Authorization: auth, "Content-Type": "text/plain" }, body: "unexpected"
		});
		assert.equal(noCsrfWithBody.status, 403);
		assert.equal((await noCsrfWithBody.json()).code, "ACTION_CSRF_INVALID");

		const withBody = await request(baseUrl, "/api/device/restart", {
			method: "POST", body: "unexpected=1"
		});
		assert.equal(withBody.status, 400);
		assert.deepEqual(await withBody.json(), {
			success: false, code: "ACTION_INPUT_INVALID", data: {}, detail: "body"
		});

		const accepted = await request(baseUrl, "/api/device/restart", { method: "POST" });
		assert.equal(accepted.status, 200);
		assert.deepEqual(await accepted.json(), {
			success: true, code: "ACTION_DEVICE_RESTARTING", data: {}, detail: ""
		});
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
	});

	await withServer(async (baseUrl) => {
		const start = await form(baseUrl, "/api/config/restore/start", { size: 60 });
		assert.equal(start.status, 201);
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
	});

	let clock = Date.now();
	const fixture = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	await withServer(async (baseUrl) => {
		const exportRequest = await form(baseUrl, "/api/config/export", {
			passphrase: fixture.passphrase
		});
		assert.equal(exportRequest.status, 202);
		// Advance past the request-time TTL while the encryption job is still pending.
		// The firmware starts the download TTL when encryption completes.
		clock += 120001;
		const ready = await completed(baseUrl, exportRequest);
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
		clock += 120001;
		const accepted = await request(baseUrl, "/api/device/restart", { method: "POST" });
		assert.equal(accepted.status, 200);
		assert.equal((await accepted.json()).code, "ACTION_DEVICE_RESTARTING");
		assert.ok(ready.data.exportId);
	}, { now: () => clock, jobDelayMs: 100 });

	await withServer(async (baseUrl) => {
		const pending = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(pending.status, 202);
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
	}, { jobDelayMs: 100 });

	await withServer(async (baseUrl) => {
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 1, push0name: "Restart interlock",
			push0url: "https://push.example/message"
		}))).success, true);
		assert.equal((await request(baseUrl, "/api/push/test?channel=0", { method: "POST" })).status, 202);
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
	}, { jobDelayMs: 100 });

	await withServer(async (baseUrl) => {
		assert.equal((await restore(baseUrl, Buffer.from(fixture.smscfgHex, "hex"), fixture.passphrase)).code,
			"ACTION_CONFIG_RESTORED");
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }),
			409, "ACTION_BUSY");
	});
});

test("queue-full export admission leaves no pending download transfer", async () => {
	const fixture = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	await withServer(async (baseUrl) => {
		const active = await Promise.all(Array.from({ length: 3 }, () =>
			request(baseUrl, "/ping", { method: "POST" })));
		assert.deepEqual(active.map(({ status }) => status), [202, 202, 202]);
		await assertAction(await form(baseUrl, "/api/config/export", {
			passphrase: fixture.passphrase
		}), 429, "ACTION_JOB_QUEUE_FULL");
		await Promise.all(active.map((response) => completed(baseUrl, response)));
		// A rejected export must not leave a download transfer that blocks restart.
		const accepted = await request(baseUrl, "/api/device/restart", { method: "POST" });
		assert.equal(accepted.status, 200);
		assert.equal((await accepted.json()).code, "ACTION_DEVICE_RESTARTING");
	}, { jobDelayMs: 100 });
});

test("pending push tests expire to a terminal result and release configuration saves", async () => {
	let clock = Date.now();
	await withServer(async (baseUrl) => {
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			push0en: "on", push0type: 1, push0name: "Expiring",
			push0url: "https://push.example/message"
		}))).success, true);
		assert.equal((await request(baseUrl, "/api/push/test?channel=0", { method: "POST" })).status, 202);
		clock += 60001;
		const expired = await (await request(baseUrl, "/api/push/test?channel=0")).json();
		assert.deepEqual([expired.queued, expired.running, expired.done, expired.success],
			[false, false, true, false]);
		assert.match(expired.message, /timed out/i);
		assert.equal((await form(baseUrl, "/save", { pushEnabled: "0" })).status, 202);
	}, { jobDelayMs: 100, now: () => clock });
});

test("forwarding rules round-trip exactly and rejected saves leave routing unchanged", async () => {
	await withServer(async (baseUrl) => {
		const rules = "from\t^\\+886\\d+$\temail,push1\nkw\t驗證碼\tpush2\t1";
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { forwardRules: rules }))).code,
			"ACTION_CONFIG_SAVED");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, rules);
		const mixed = await completed(baseUrl, await form(baseUrl, "/save", {
			forwardRules: rules, adminPhone: "must-not-save"
		}));
		assert.deepEqual([mixed.code, mixed.detail], ["ACTION_CONFIG_INVALID", "forwardRules"]);
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.adminPhone, "");

		const tooLong = await form(baseUrl, "/save", { forwardRules: "界".repeat(683) });
		assert.equal(tooLong.status, 400);
		assert.deepEqual(await tooLong.json(), {
			success: false, code: "ACTION_INPUT_TOO_LONG", data: {}, detail: "forwardRules"
		});
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, rules);

		const invalid = await completed(baseUrl, await form(baseUrl, "/save", { forwardRules: "re\t[\temail" }));
		assert.deepEqual([invalid.success, invalid.code, invalid.detail], [false, "ACTION_CONFIG_INVALID", "forwardRules"]);
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, rules);

		const posixInvalid = await completed(baseUrl, await form(baseUrl, "/save", {
			forwardRules: "re\t(?=a)\temail"
		}));
		assert.deepEqual([posixInvalid.success, posixInvalid.code, posixInvalid.detail],
			[false, "ACTION_CONFIG_INVALID", "forwardRules"]);
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.forwardRules, rules);

		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { adminPhone: "+886900000000" }))).code,
			"ACTION_CONFIG_SAVED");
		const snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.adminPhone, "+886900000000");
		assert.equal(snapshot.config.forwardRules, rules);
	});
});

test("one save family and current limits reject without mutation", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { adminPhone: "1".repeat(64) }))).success, true);
		const tooLong = await form(baseUrl, "/save", { adminPhone: "1".repeat(65) });
		assert.equal(tooLong.status, 400);
		assert.equal((await tooLong.json()).detail, "adminPhone");
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			smtpServer: "smtp.example.com", smtpUser: "sender@example.com", smtpPass: "secret", smtpSendTo: "a".repeat(256)
		}))).success, true);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { smtpPass: "" }))).success, true);
		assert.equal((await (await request(baseUrl, "/api/config")).json()).status.emailConfigured, false);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			kaIntervalDays: 3650, kaTrafficKB: 10000
		}))).success, true);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { kaTrafficKB: 10001 }))).code,
			"ACTION_CONFIG_INVALID");
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			smtpServer: "must-not-save.example", networkMode: 2
		}))).code, "ACTION_CONFIG_INVALID");
		const snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.smtpServer, "smtp.example.com");
		assert.equal(snapshot.config.networkMode, 0);
		assert.equal(snapshot.config.kaTrafficKB, 10000);
	});
});

test("keepalive preserves disabled compatibility values and rejects unsafe enablement atomically", async () => {
	await withServer(async (baseUrl) => {
		const preserved = await form(baseUrl, "/save", {
			kaIntervalDays: 200, kaTrafficKB: 4321
		});
		assert.equal(preserved.status, 202);
		assert.equal((await completed(baseUrl, preserved)).code, "ACTION_CONFIG_SAVED");
		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.kaEnabled, snapshot.config.kaIntervalDays, snapshot.config.kaTrafficKB
		], [false, 200, 4321]);
		const unsafe = await completed(baseUrl, await form(baseUrl, "/save", { kaEnabled: "on", kaIntervalDays: 201, kaTrafficKB: 4321 }));
		assert.equal(unsafe.code, "ACTION_CONFIG_INVALID");
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([snapshot.config.kaEnabled, snapshot.config.kaIntervalDays, snapshot.config.kaTrafficKB], [false, 200, 4321]);

		const disabled = await form(baseUrl, "/save", { kaIntervalDays: 200, kaTrafficKB: 4321 });
		assert.equal(disabled.status, 202);
		assert.equal((await completed(baseUrl, disabled)).code, "ACTION_CONFIG_SAVED");
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.kaEnabled, snapshot.config.kaIntervalDays, snapshot.config.kaTrafficKB
		], [false, 200, 4321]);
	});
});

test("jobs expose six slots, at most three active, and a 60-second terminal TTL", async () => {
	let clock = 1000;
	await withServer(async (baseUrl) => {
		const ids = [];
		for (let index = 0; index < 6; index += 1) {
			const response = await request(baseUrl, "/ping", { method: "POST" });
			assert.equal(response.status, 202);
			ids.push((await response.json()).data.jobId);
		}
		const full = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(full.status, 429);
		assert.equal((await full.json()).code, "ACTION_JOB_QUEUE_FULL");
		clock += 60000;
		assert.equal((await request(baseUrl, `/api/jobs?id=${ids[0]}`)).status, 404);
		assert.equal((await request(baseUrl, "/ping", { method: "POST" })).status, 202);
	}, { now: () => clock });
	await withServer(async (baseUrl) => {
		const active = await Promise.all(Array.from({ length: 3 }, () => request(baseUrl, "/ping", { method: "POST" })));
		assert.deepEqual(active.map((response) => response.status), [202, 202, 202]);
		assert.equal((await request(baseUrl, "/ping", { method: "POST" })).status, 429);
	}, { jobDelayMs: 100 });
});

test("log pages are chronological and bounded", async () => {
	await withServer(async (baseUrl) => {
		const latest = await (await request(baseUrl, "/log?limit=1")).json();
		assert.equal(latest.entries.length, 1);
		assert.equal(latest.hasMore, true);
		const older = await (await request(baseUrl, `/log?limit=1&cursor=${latest.nextCursor}`)).json();
		assert.ok(older.entries.every((entry) => entry.id < latest.nextCursor));
		assert.equal((await request(baseUrl, "/log?limit=51")).status, 400);
		assert.equal((await request(baseUrl, "/log?cursor=bad")).status, 400);
	});
});

test("the independent v6 fixture restores with legacy defaults and re-exports as v7", async () => {
	const fixture = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	const encrypted = Buffer.from(fixture.smscfgHex, "hex");
	const plaintext = decrypt(encrypted, fixture.passphrase);
	assert.equal(plaintext.toString("hex"), fixture.plaintextHex);
	assert.equal(plaintext.subarray(0, 4).toString(), "CFG2");
	assert.equal(plaintext.readUInt16LE(4), 6);
	assert.equal(plaintext.readUInt32LE(8), 0);
	assert.equal(plaintext.readUInt32LE(12), plaintext.length - 20);
	assert.equal(plaintext.readUInt32LE(16), crc32(plaintext.subarray(20)));
	await withServer(async (baseUrl) => {
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			deviceName: "Target gateway", hostname: "target-gateway"
		}))).success, true);
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", {
			account1user: "operator", account1pass: "operator-secret"
		}))).success, true);
		assert.equal((await restore(baseUrl, encrypted, fixture.passphrase)).code, "ACTION_CONFIG_RESTORED");
		const snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.deviceName, snapshot.config.hostname, snapshot.config.webAccounts[1].username,
			snapshot.config.notificationLocale, snapshot.config.smtpServer, snapshot.config.wifiProfiles[0].ssid,
			snapshot.config.networkMode, snapshot.config.heartbeatEnable, snapshot.config.heartbeatInterval,
			snapshot.config.kaEnabled, snapshot.config.kaIntervalDays, snapshot.config.kaTrafficKB
		], ["Target gateway", "target-gateway", "operator", "en", "smtp.example.com", "Office WiFi", 2, false, 24, true, 200, 4321]);
		const ready = await completed(baseUrl, await form(baseUrl, "/api/config/export", { passphrase: fixture.passphrase }));
		const response = await request(baseUrl, `/api/config/export?id=${ready.data.exportId}`);
		assert.equal(response.headers.get("x-config-schema-version"), "7");
		const exported = decrypt(await response.arrayBuffer(), fixture.passphrase);
		assert.equal(exported.readUInt16LE(4), 7);
		assert.equal(exported.readUInt32LE(12), exported.length - 20);
		assert.equal(exported.readUInt32LE(16), crc32(exported.subarray(20)));
		assert.notEqual(exported.toString("hex"), fixture.plaintextHex);
	});
});

test("signed OTA validates canonical signature, payload hash, and replay counter", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const firmware = Buffer.from([0xe9, 1, 2, 3]);
	const manifest = (counter, hash = createHash("sha256").update(firmware).digest("hex")) =>
		JSON.stringify({ format: 1, releaseCounter: counter, sha256: hash, size: firmware.length, target: "esp32c3", version: `1.2.${counter}` });
	const signature = (text) => sign("sha256", Buffer.from(text), privateKey).toString("hex");
	await withServer(async (baseUrl) => {
		const text = manifest(1);
		const invalid = await form(baseUrl, "/api/ota/start", { manifest: text, signature: "00".repeat(8) });
		assert.equal((await invalid.json()).code, "ACTION_OTA_SIGNATURE_INVALID");
		const start = await form(baseUrl, "/api/ota/start", { manifest: text, signature: signature(text) });
		assert.equal(start.status, 201);
		const id = (await start.json()).data.uploadId;
		assert.equal((await request(baseUrl, `/api/ota/chunk?id=${id}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		})).status, 200);
		assert.equal((await completed(baseUrl, await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" }))).code,
			"ACTION_OTA_READY");
		assert.equal((await (await form(baseUrl, "/api/ota/start", { manifest: text, signature: signature(text) })).json()).code,
			"ACTION_OTA_MANIFEST_INVALID");
		const badText = manifest(2, "0".repeat(64));
		const badStart = await form(baseUrl, "/api/ota/start", { manifest: badText, signature: signature(badText) });
		const badId = (await badStart.json()).data.uploadId;
		await request(baseUrl, `/api/ota/chunk?id=${badId}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		});
		assert.equal((await completed(baseUrl, await request(baseUrl, `/api/ota/finish?id=${badId}`, { method: "POST" }))).code,
			"ACTION_OTA_HASH_INVALID");
	}, { otaPublicKey: publicKey });
});

test("method, CSRF, and AP provisioning exceptions use the exact firmware routes", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/config`, { method: "HEAD", headers: { Authorization: auth } })).status, 405);
		assert.equal((await fetch(`${baseUrl}/flight?action=query`, { headers: { Authorization: auth } })).status, 403);
		assert.notEqual((await fetch(`${baseUrl}/query?type=ati`, { headers: { Authorization: auth } })).status, 403);
	});
	await withServer(async (baseUrl) => {
		const root = await fetch(`${baseUrl}/`);
		assert.equal(root.status, 200);
		assert.equal(await root.text(), await readFile(new URL("../../web/build/provisioning.html", import.meta.url), "utf8"));
		assert.equal((await fetch(`${baseUrl}/wificonfig?x=1`, {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "X-SMS-CSRF": "1" },
			body: "ssid=Office&pass=wifi-secret"
		})).status, 401);
	}, { apLocalAddress: "127.0.0.1", webRoot: new URL("../../web/build/", import.meta.url).pathname });
});

test("a full job table rejects restore before decoding or changing configuration", async () => {
	const fixture = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	await withServer(async (baseUrl) => {
		const bytes = Buffer.from(fixture.smscfgHex, "hex");
		const start = await form(baseUrl, "/api/config/restore/start", { size: bytes.length });
		const id = (await start.json()).data.uploadId;
		await request(baseUrl, `/api/config/restore/chunk?id=${id}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: bytes.toString("base64")
		});
		for (let index = 0; index < 6; index += 1) assert.equal((await request(baseUrl, "/ping", { method: "POST" })).status, 202);
		await assertAction(await form(baseUrl, `/api/config/restore/finish?id=${id}`, { passphrase: fixture.passphrase }),
			429, "ACTION_JOB_QUEUE_FULL");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.networkMode, 0);
	});
});

test("fixed legacy vectors migrate provider type zero and decoded ranges reject atomically", async () => {
	const legacy = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v1.json", import.meta.url), "utf8"));
	const current = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	for (const version of [1, 2, 3, 4]) {
		await withServer(async (baseUrl) => {
			const bytes = encryptPlaintext(Buffer.from(legacy.legacyTypeZeroPlaintextHex[version], "hex"), legacy.passphrase);
			assert.equal((await restore(baseUrl, bytes, legacy.passphrase)).code, "ACTION_CONFIG_RESTORED");
			assert.deepEqual((await (await request(baseUrl, "/api/config")).json()).config.pushChannels.map(({ type }) => type),
				[1, 1, 1, 1, 1]);
		});
	}
	await withServer(async (baseUrl) => {
		const bytes = encryptPlaintext(Buffer.from(current.invalidKaActionPlaintextHex, "hex"), current.passphrase);
		assert.equal((await restore(baseUrl, bytes, current.passphrase)).code, "ACTION_CONFIG_RESTORE_INVALID");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.networkMode, 0);
	});
});

test("restore transfer values are strict uint32 and invalid finish input is immediate", async () => {
	await withServer(async (baseUrl) => {
		await assertAction(await form(baseUrl, "/api/config/restore/start", { size: "60x" }), 400, "ACTION_CONFIG_RESTORE_INVALID");
		const start = await form(baseUrl, "/api/config/restore/start", { size: 60 });
		const id = (await start.json()).data.uploadId;
		await assertAction(await request(baseUrl, `/api/config/restore/chunk?id=${id}x&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: Buffer.alloc(3).toString("base64")
		}), 409, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
		await assertAction(await form(baseUrl, `/api/config/restore/finish?id=${id}`, { passphrase: "short" }),
			400, "ACTION_CONFIG_PASSPHRASE_INVALID");
	});
});

test("OTA session errors, mutual exclusion, and invalid actions are immediate four-field results", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const firmware = Buffer.from([0xe9, 1, 2, 3]);
	const text = JSON.stringify({ format: 1, releaseCounter: 1,
		sha256: createHash("sha256").update(firmware).digest("hex"), size: firmware.length,
		target: "esp32c3", version: "1.2.1" });
	await withServer(async (baseUrl) => {
		const active = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(active.status, 202);
		await assertAction(await form(baseUrl, "/api/ota/start", { manifest: text,
			signature: sign("sha256", Buffer.from(text), privateKey).toString("hex") }), 409, "ACTION_BUSY");
	}, { otaPublicKey: publicKey, jobDelayMs: 100 });
	await withServer(async (baseUrl) => {
		const start = await form(baseUrl, "/api/ota/start", { manifest: text,
			signature: sign("sha256", Buffer.from(text), privateKey).toString("hex") });
		const id = (await start.json()).data.uploadId;
		await assertAction(await request(baseUrl, `/api/ota/chunk?id=${id + 1}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		}), 409, "ACTION_OTA_SESSION_INVALID");
		await assertAction(await request(baseUrl, `/api/ota/chunk?id=${id}&offset=1`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		}), 400, "ACTION_OTA_CHUNK_INVALID");
		await assertAction(await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" }),
			409, "ACTION_OTA_SESSION_INVALID");
	}, { otaPublicKey: publicKey });
	await withServer(async (baseUrl) => {
		for (const [path, code] of [["/query?type=bad", "ACTION_QUERY_UNKNOWN"],
			["/flight?action=bad", "ACTION_UNKNOWN"], ["/modem?action=bad", "ACTION_UNKNOWN"],
			["/wifi?action=bad", "ACTION_UNKNOWN"]]) {
			await assertAction(await request(baseUrl, path), 400, code);
		}
	});
});

test("portable fields validate before local overwrite and schema v5 preserves target traffic", async () => {
	const legacy = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v1.json", import.meta.url), "utf8"));
	const current = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v6.json", import.meta.url), "utf8"));
	await withServer(async (baseUrl) => {
		assert.equal((await completed(baseUrl, await form(baseUrl, "/save", { kaTrafficKB: 777 }))).success, true);
		const bytes = encryptPlaintext(Buffer.from(legacy.schemaV5PlaintextHex, "hex"), legacy.passphrase);
		assert.equal((await restore(baseUrl, bytes, legacy.passphrase)).code, "ACTION_CONFIG_RESTORED");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.kaTrafficKB, 777);
	});
	await withServer(async (baseUrl) => {
		const bytes = encryptPlaintext(Buffer.from(current.invalidLocalFieldPlaintextHex, "hex"), current.passphrase);
		assert.equal((await restore(baseUrl, bytes, current.passphrase)).code, "ACTION_CONFIG_RESTORE_INVALID");
	});
});

test("empty restore bodies return immediate four-field errors", async () => {
	await withServer(async (baseUrl) => {
		await assertAction(await request(baseUrl, "/api/config/restore/start", { method: "POST" }),
			400, "ACTION_CONFIG_RESTORE_INVALID");
		const start = await form(baseUrl, "/api/config/restore/start", { size: 60 });
		const id = (await start.json()).data.uploadId;
		await assertAction(await request(baseUrl, `/api/config/restore/finish?id=${id}`, { method: "POST" }),
			400, "ACTION_CONFIG_PASSPHRASE_INVALID");
	});
});

test("OTA incomplete, finishing, and queue-full sessions retain firmware lifecycle semantics", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const firmware = Buffer.from([0xe9, 1, 2, 3]);
	const text = JSON.stringify({ format: 1, releaseCounter: 1,
		sha256: createHash("sha256").update(firmware).digest("hex"), size: firmware.length,
		target: "esp32c3", version: "1.2.1" });
	const signed = sign("sha256", Buffer.from(text), privateKey).toString("hex");
	const startOta = async (baseUrl) => {
		const response = await form(baseUrl, "/api/ota/start", { manifest: text, signature: signed });
		return (await response.json()).data.uploadId;
	};
	await withServer(async (baseUrl) => {
		const id = await startOta(baseUrl);
		await assertAction(await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" }),
			409, "ACTION_OTA_SESSION_INVALID");
		await assertAction(await request(baseUrl, `/api/ota/chunk?id=${id}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		}), 409, "ACTION_OTA_SESSION_INVALID");
	}, { otaPublicKey: publicKey });
	await withServer(async (baseUrl) => {
		const id = await startOta(baseUrl);
		await request(baseUrl, `/api/ota/chunk?id=${id}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		});
		const finish = await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" });
		assert.equal(finish.status, 202);
		await assertAction(await request(baseUrl, "/ping", { method: "POST" }), 409, "ACTION_BUSY");
		await completed(baseUrl, finish);
		await assertAction(await request(baseUrl, "/api/device/restart", { method: "POST" }), 409, "ACTION_BUSY");
	}, { otaPublicKey: publicKey, jobDelayMs: 100 });
	let clock = 1000;
	await withServer(async (baseUrl) => {
		for (let index = 0; index < 6; index += 1) assert.equal((await request(baseUrl, "/ping", { method: "POST" })).status, 202);
		const id = await startOta(baseUrl);
		await request(baseUrl, `/api/ota/chunk?id=${id}&offset=0`, {
			method: "POST", headers: { "Content-Type": "text/plain" }, body: firmware.toString("base64")
		});
		await assertAction(await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" }),
			429, "ACTION_JOB_QUEUE_FULL");
		clock += 60000;
		assert.equal((await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" })).status, 202);
	}, { otaPublicKey: publicKey, now: () => clock });
});

test("missing AT and query parameters are immediate input errors", async () => {
	await withServer(async (baseUrl) => {
		await assertAction(await request(baseUrl, "/at"), 400, "ACTION_AT_REJECTED");
		await assertAction(await request(baseUrl, "/query"), 400, "ACTION_INPUT_INVALID");
	});
});

test("modern eSIM contract masks identifiers and rejects stale or unsafe actions", async () => {
	await withServer(async (baseUrl) => {
		const unauthorized = await fetch(`${baseUrl}/api/esim`);
		assert.equal(unauthorized.status, 401);
		assert.equal(unauthorized.headers.get("cache-control"), "no-store, max-age=0");

		const initial = await request(baseUrl, "/api/esim");
		assert.equal(initial.status, 200);
		assert.equal(initial.headers.get("cache-control"), "no-store, max-age=0");
		const status = await initial.json();
		assert.deepEqual(Object.keys(status).sort(), ["eid", "job", "profiles"]);
		assert.deepEqual(Object.keys(status.eid).sort(), ["available", "length", "state"]);
		assert.equal(typeof status.eid.available, "boolean");
		assert.equal(typeof status.eid.length, "number");
		assert.ok(status.profiles.length > 0);
		assert.ok(status.profiles.every((profile) => {
			assert.deepEqual(Object.keys(profile).sort(), ["displayId", "handle", "nickname", "profileClass", "state"]);
			assert.equal(typeof profile.handle, "string");
			assert.equal(typeof profile.displayId, "string");
			assert.equal(profile.displayId, "••••");
			return !JSON.stringify(profile).includes("8901234567890123456");
		}));
		assert.equal(JSON.stringify(status).includes("8901234567890123456"), false);

		const query = await request(baseUrl, "/api/esim?unexpected=1");
		assert.equal(query.status, 400);
		assert.equal(query.headers.get("cache-control"), "no-store, max-age=0");
		assert.equal((await query.json()).code, "ACTION_INPUT_INVALID");

		const handle = status.profiles[0].handle;
		const noCsrf = await fetch(`${baseUrl}/api/esim`, {
			method: "POST", headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ action: "nickname", handle, nickname: "New name" })
		});
		assert.equal(noCsrf.status, 403);
		assert.equal(noCsrf.headers.get("cache-control"), "no-store, max-age=0");
		assert.equal((await noCsrf.json()).code, "ACTION_CSRF_INVALID");

		const malformedHandle = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "delete", handle: "bad" })
		});
		assert.equal(malformedHandle.status, 400);
		assert.equal(malformedHandle.headers.get("cache-control"), "no-store, max-age=0");
		assert.equal((await malformedHandle.json()).code, "ACTION_INPUT_INVALID");

		const unknownHandle = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "delete", handle: "p0000000000000000" })
		});
		assert.equal(unknownHandle.status, 409);
		assert.equal(unknownHandle.headers.get("cache-control"), "no-store, max-age=0");
		assert.equal((await unknownHandle.json()).code, "ACTION_ESIM_HANDLE_STALE");

		const invalidNickname = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "nickname", handle, nickname: "x".repeat(65) })
		});
		assert.equal(invalidNickname.status, 400);
		assert.equal(invalidNickname.headers.get("cache-control"), "no-store, max-age=0");
		assert.equal((await invalidNickname.json()).code, "ACTION_INPUT_TOO_LONG");

		const accepted = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "nickname", handle, nickname: "New name" })
		});
		assert.equal(accepted.status, 202);
		assert.equal(accepted.headers.get("cache-control"), "no-store, max-age=0");
		const acceptedBody = await accepted.json();
		assert.deepEqual(Object.keys(acceptedBody).sort(), ["code", "data", "detail", "success"]);
		assert.equal(acceptedBody.code, "ACTION_JOB_ACCEPTED");
		assert.equal(typeof acceptedBody.data.jobId, "number");

		const staleRefresh = await request(baseUrl, "/api/esim", { method: "POST", body: new URLSearchParams({ action: "refresh" }) });
		assert.equal(staleRefresh.status, 202);
		const stale = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "delete", handle })
		});
		assert.equal(stale.status, 409);
		assert.equal((await stale.json()).code, "ACTION_ESIM_HANDLE_STALE");

		const unsupportedMethod = await request(baseUrl, "/api/esim", { method: "PUT" });
		assert.equal(unsupportedMethod.status, 405);
		assert.equal(unsupportedMethod.headers.get("allow"), "GET, POST");
		assert.equal(unsupportedMethod.headers.get("cache-control"), "no-store, max-age=0");
	});
});

test("eSIM and API jobs admit in one direction at a time", async () => {
	await withServer(async (baseUrl) => {
		const apiPending = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(apiPending.status, 202);
		const esimBlocked = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "refresh" })
		});
		assert.equal(esimBlocked.status, 409);
		assert.equal((await esimBlocked.json()).code, "ACTION_ESIM_BUSY");
		await completed(baseUrl, apiPending);

		const esimPending = await request(baseUrl, "/api/esim", {
			method: "POST", body: new URLSearchParams({ action: "refresh" })
		});
		assert.equal(esimPending.status, 202);
		const apiBlocked = await request(baseUrl, "/ping", { method: "POST" });
		assert.equal(apiBlocked.status, 409);
		assert.equal((await apiBlocked.json()).code, "ACTION_BUSY");
	}, { jobDelayMs: 100 });
});

test("eSIM installation binds one confirmation to its active job without exposing secrets", async () => {
	await withServer(async (baseUrl) => {
		const activationCode = "LPA:1$example.invalid$INSTALL-SECRET";
		const pending = await form(baseUrl, "/api/esim", { action: "install", activationCode });
		assert.equal(pending.status, 202);
		const { data: { jobId } } = await pending.json();
		const status = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(status.job.id, jobId);
		assert.equal(status.job.stage, "awaiting_confirmation");
		assert.equal(status.job.confirmationRequired, true);
		assert.equal(status.job.state, "running");
		assert.equal(JSON.stringify(status).includes("INSTALL-SECRET"), false);
		await assertAction(await form(baseUrl, "/api/esim", { action: "refresh" }), 409, "ACTION_ESIM_BUSY");
		assert.equal(status.job.profileName, "Installed profile");
		assert.equal(status.job.providerName, "Example carrier");
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId: jobId + 1, accepted: "true", confirmationCode: "private-code" }), 409, "ACTION_ESIM_CONFIRMATION_STALE");
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true", confirmationCode: "x".repeat(129) }), 400, "ACTION_INPUT_INVALID");
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true" }), 400, "ACTION_INPUT_INVALID");
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true", confirmationCode: "private-code", nickname: "extra" }), 400, "ACTION_INPUT_INVALID");
		const confirm = await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true", confirmationCode: "private-code" });
		assert.equal(confirm.status, 202);
		assert.equal((await confirm.json()).data.jobId, jobId);
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true", confirmationCode: "private-code" }), 409, "ACTION_ESIM_CONFIRMATION_STALE");
		const finished = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(finished.job.state, "succeeded");
		assert.equal(finished.job.confirmationRequired, false);
		assert.equal(finished.job.stage, "completed");
		assert.equal(finished.profiles.at(-1).state, "disabled");
		assert.equal(JSON.stringify(finished).includes("private-code"), false);
	}, { esimConfirmationRequired: true });
});

test("installed eSIM remains successful when server notification is pending", async () => {
	await withServer(async (baseUrl) => {
		const before = await (await request(baseUrl, "/api/esim")).json();
		assert.equal((await form(baseUrl, "/api/esim", { action: "install", activationCode: "LPA:1$example.invalid$PENDING-NOTIFICATION" })).status, 202);
		const pending = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(pending.job.stage, "awaiting_confirmation");
		assert.equal(pending.job.confirmationRequired, false);
		assert.equal(pending.profiles.length, before.profiles.length);
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId: pending.job.id, accepted: "true", confirmationCode: "unrequested" }), 400, "ACTION_INPUT_INVALID");
		assert.equal((await form(baseUrl, "/api/esim", { action: "confirm", jobId: pending.job.id, accepted: "true" })).status, 202);
		const after = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(after.job.state, "succeeded");
		assert.equal(after.job.success, true);
		assert.equal(after.job.notificationPending, true);
		assert.equal(after.job.code, "ACTION_ESIM_NOTIFICATION_PENDING");
		assert.equal(after.profiles.length, before.profiles.length + 1);
		assert.equal(after.profiles.find((profile) => profile.state === "enabled")?.nickname, "Primary");
	}, { esimNotificationPending: true });
});

test("eSIM confirmation expires without another status request and releases admission", async () => {
	const timers = [];
	let clock = 1000;
	await withServer(async (baseUrl) => {
		const accepted = await form(baseUrl, "/api/esim", { action: "install", activationCode: "LPA:1$example.invalid$EXPIRY" });
		assert.equal(accepted.status, 202);
		const { data: { jobId } } = await accepted.json();
		assert.equal(timers.length, 1);
		clock += timers[0].delay;
		timers[0].run();
		await assertAction(await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "true", confirmationCode: "late" }), 409, "ACTION_ESIM_CONFIRMATION_STALE");
		const status = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(status.job.state, "failed");
		assert.equal(status.job.confirmationRequired, false);
		assert.equal((await form(baseUrl, "/api/esim", { action: "refresh" })).status, 202);
	}, { esimConfirmationRequired: true, now: () => clock,
		esimSchedule: (run, delay) => { timers.push({ run, delay }); } });
});

test("postponing eSIM consent makes no profile change and releases the active job", async () => {
	await withServer(async (baseUrl) => {
		const before = await (await request(baseUrl, "/api/esim")).json();
		const accepted = await form(baseUrl, "/api/esim", { action: "install", activationCode: "LPA:1$example.invalid$POSTPONE" });
		assert.equal(accepted.status, 202);
		const { data: { jobId } } = await accepted.json();
		assert.equal((await form(baseUrl, "/api/esim", { action: "confirm", jobId, accepted: "false" })).status, 202);
		const status = await (await request(baseUrl, "/api/esim")).json();
		assert.equal(status.job.code, "ACTION_ESIM_POSTPONED");
		assert.deepEqual(status.profiles, before.profiles);
		assert.equal((await form(baseUrl, "/api/esim", { action: "refresh" })).status, 202);
	});
});
