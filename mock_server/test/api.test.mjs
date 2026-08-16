import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createApp } from "../server.mjs";

const auth = `Basic ${Buffer.from("admin:admin123").toString("base64")}`;

function crc32(bytes) {
	let crc = 0xffffffff;
	for (const byte of bytes) {
		crc ^= byte;
		for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

function decryptBackup(bytes, passphrase) {
	const buffer = Buffer.from(bytes);
	assert.equal(buffer.subarray(0, 8).toString(), "SMSCFG01");
	assert.equal(buffer.readUInt16LE(8), 1);
	assert.equal(buffer[10], 1);
	assert.equal(buffer[11], 1);
	assert.equal(buffer.readUInt32LE(12), 210000);
	const decipher = createDecipheriv("aes-256-gcm", pbkdf2Sync(passphrase, buffer.subarray(16, 32), 210000, 32, "sha256"), buffer.subarray(32, 44));
	decipher.setAAD(buffer.subarray(0, 44));
	decipher.setAuthTag(buffer.subarray(-16));
	return Buffer.concat([decipher.update(buffer.subarray(44, -16)), decipher.final()]);
}

function encryptBackup(portable, passphrase) {
	const salt = randomBytes(16);
	const iv = randomBytes(12);
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
	return Buffer.concat([header, cipher.update(portable), cipher.final(), cipher.getAuthTag()]);
}

async function withServer(run, options) {
	const server = createApp(options).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	try {
		await run(`http://127.0.0.1:${server.address().port}`);
	} finally {
		await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
	}
}

function request(baseUrl, path, init = {}) {
	return fetch(`${baseUrl}${path}`, {
		...init,
		headers: { Authorization: auth, "X-CSRF-Token": "mock-csrf-token", ...init.headers }
	});
}

function base64Body(bytes) {
	return { headers: { "Content-Type": "text/plain" }, body: Buffer.from(bytes).toString("base64") };
}

function firstPushTypeOffset(portable) {
	let offset = 24;
	for (let index = 0; index < 29; index += 1) offset += 2 + portable.readUInt16LE(offset);
	return offset + 1;
}

function portableV1() {
	const string = (value) => {
		const bytes = Buffer.from(value);
		const length = Buffer.alloc(2);
		length.writeUInt16LE(bytes.length);
		return Buffer.concat([length, bytes]);
	};
	const port = Buffer.alloc(4);
	port.writeUInt32LE(465);
	const fields = ["smtp.example.com", "sender@example.com", "smtp-secret", "to@example.com", "", ""].map(string);
	const accounts = Array.from({ length: 10 }, () => Buffer.concat([string(""), string("")]));
	const channel = Buffer.concat([Buffer.from([0, 1]), ...["Channel", "", "", "", ""].map(string)]);
	const payload = Buffer.concat([port, ...fields, ...accounts, ...Array.from({ length: 5 }, () => channel)]);
	const header = Buffer.alloc(20);
	header.write("CFG2");
	header.writeUInt16LE(1, 4);
	header.writeUInt32LE(payload.length, 12);
	header.writeUInt32LE(crc32(payload), 16);
	return Buffer.concat([header, payload]);
}

async function completedAction(baseUrl, response) {
	const body = await response.json();
	if (response.status !== 202 || body.code !== "ACTION_JOB_ACCEPTED") return body;
	const job = await (await request(baseUrl, `/api/jobs?id=${body.data.jobId}`)).json();
	return job.result;
}

test("authentication can be disabled for the LAN development server", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/config`)).status, 200);
		assert.equal((await fetch(`${baseUrl}/query?type=wifi`)).status, 202);
		assert.equal((await fetch(`${baseUrl}/flight?action=query`)).status, 202);
		assert.equal((await fetch(`${baseUrl}/flight?action=toggle`)).status, 403);
		assert.equal((await fetch(`${baseUrl}/at?cmd=AT`)).status, 403);
		assert.equal((await fetch(`${baseUrl}/modem?action=restart`)).status, 403);
		assert.equal((await fetch(`${baseUrl}/wifi?action=restart`)).status, 403);
	}, { authRequired: false });
});

test("push provider secrets stay masked and retained without crossing provider types", async () => {
	await withServer(async (baseUrl) => {
		for (const [index, type, name, url, key1] of [
			[0, 9, "Gotify", "https://gotify.example/message", "gotify-token"],
			[1, 12, "ntfy", "https://ntfy.sh/example-topic", ""],
			[2, 11, "Discord", "https://discord.com/api/webhooks/id/token", ""]
		]) {
			const response = await request(baseUrl, "/save", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					[`push${index}en`]: "on",
					[`push${index}type`]: String(type),
					[`push${index}name`]: name,
					[`push${index}url`]: url,
					[`push${index}key1`]: key1,
					[`push${index}key2`]: "",
					[`push${index}body`]: "",
					[`push${index}title`]: "Alert from {sender}",
					[`push${index}template`]: "{message}"
				})
			});
			assert.equal((await completedAction(baseUrl, response)).code, "ACTION_CONFIG_SAVED");
		}

		let channels = (await (await request(baseUrl, "/api/config")).json()).config.pushChannels;
		assert.deepEqual(channels.slice(0, 3).map(({ type, url, urlSet, key1, key1Set, key2, key2Set, customBody, customBodySet }) => (
			{ type, url, urlSet, key1, key1Set, key2, key2Set, customBody, customBodySet }
		)), [
			{ type: 9, url: "", urlSet: true, key1: "", key1Set: true, key2: "", key2Set: false, customBody: "", customBodySet: false },
			{ type: 12, url: "", urlSet: true, key1: "", key1Set: false, key2: "", key2Set: false, customBody: "", customBodySet: false },
			{ type: 11, url: "", urlSet: true, key1: "", key1Set: false, key2: "", key2Set: false, customBody: "", customBodySet: false }
		]);

		const enabledOnly = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ push0en: "on" })
		});
		assert.equal((await completedAction(baseUrl, enabledOnly)).code, "ACTION_CONFIG_SAVED");
		channels = (await (await request(baseUrl, "/api/config")).json()).config.pushChannels;
		assert.deepEqual({
			type: channels[0].type, name: channels[0].name,
			titleTemplate: channels[0].titleTemplate, bodyTemplate: channels[0].bodyTemplate,
			urlSet: channels[0].urlSet, key1Set: channels[0].key1Set
		}, {
			type: 9, name: "Gotify", titleTemplate: "Alert from {sender}", bodyTemplate: "{message}",
			urlSet: true, key1Set: true
		});

		const ordinarySave = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				push0en: "on", push0name: "Renamed Gotify",
				push0url: "", push0key1: "", push0key2: "", push0body: "",
				push0title: "Updated {sender}", push0template: "{message}"
			})
		});
		assert.equal((await completedAction(baseUrl, ordinarySave)).code, "ACTION_CONFIG_SAVED");
		channels = (await (await request(baseUrl, "/api/config")).json()).config.pushChannels;
		assert.deepEqual({ name: channels[0].name, urlSet: channels[0].urlSet, key1Set: channels[0].key1Set }, {
			name: "Renamed Gotify", urlSet: true, key1Set: true
		});

		const changedProvider = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ push0en: "on", push0type: "10", push0name: "Telegram", push0title: "{sender}", push0template: "{message}" })
		});
		assert.equal((await completedAction(baseUrl, changedProvider)).code, "ACTION_CONFIG_SAVED");
		channels = (await (await request(baseUrl, "/api/config")).json()).config.pushChannels;
		assert.deepEqual({ type: channels[0].type, urlSet: channels[0].urlSet, key1Set: channels[0].key1Set, key2Set: channels[0].key2Set }, {
			type: 10, urlSet: false, key1Set: false, key2Set: false
		});

		const invalid = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ push0type: "13" })
		});
		assert.equal((await completedAction(baseUrl, invalid)).code, "ACTION_CONFIG_INVALID");
	});
});

test("schema v2 portable configs still reject provider values added in v3", async () => {
	const vector = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v1.json", import.meta.url), "utf8"));
	const portable = decryptBackup(Buffer.from(vector.smscfgHex, "hex"), vector.passphrase);
	assert.equal(portable.readUInt16LE(4), 2);
	portable[firstPushTypeOffset(portable)] = 11;
	portable.writeUInt32LE(crc32(portable.subarray(20)), 16);
	const passphrase = "correct horse battery staple";
	const encrypted = encryptBackup(portable, passphrase);

	await withServer(async (baseUrl) => {
		const started = await request(baseUrl, "/api/config/restore/start", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ size: String(encrypted.length) })
		});
		const uploadId = (await started.json()).data.uploadId;
		assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${uploadId}&offset=0`, {
			method: "POST", ...base64Body(encrypted)
		})).status, 200);
		const finished = await request(baseUrl, `/api/config/restore/finish?id=${uploadId}`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ passphrase })
		});
		assert.equal((await completedAction(baseUrl, finished)).code, "ACTION_CONFIG_RESTORE_INVALID");
	});
});

test("WiFi profiles and scheduled connectivity settings support partial updates", async () => {
	await withServer(async (baseUrl) => {
		const initial = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual(initial.config.wifiProfiles, Array.from({ length: 5 }, () => ({ ssid: "", password: "", open: false })));
		assert.deepEqual({
			networkMode: initial.config.networkMode,
			heartbeatEnable: initial.config.heartbeatEnable,
			heartbeatInterval: initial.config.heartbeatInterval
		}, {
			networkMode: 0,
			heartbeatEnable: true,
			heartbeatInterval: 6
		});

		const save = (body) => request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(body)
		});
		assert.equal((await completedAction(baseUrl, await save({
			wifi0ssid: "Office WiFi", wifi0pass: "first-secret", networkMode: "2",
			heartbeatEnable: "on", heartbeatInterval: "12"
		}))).code, "ACTION_CONFIG_SAVED");

		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual(snapshot.config.wifiProfiles[0], { ssid: "Office WiFi", password: "", open: false });
		assert.equal(snapshot.config.networkMode, 2);
		assert.equal(snapshot.config.heartbeatInterval, 12);

		assert.equal((await completedAction(baseUrl, await save({ wifi0ssid: "Office WiFi" }))).success, true);
		const missingPassword = await completedAction(baseUrl, await save({ wifi0ssid: "No password" }));
		assert.deepEqual(missingPassword, {
			success: false, code: "ACTION_WIFI_PASSWORD_REQUIRED", data: {}, detail: "wifi0ssid"
		});
		assert.equal((await completedAction(baseUrl, await save({ wifi1ssid: "Too short", wifi1pass: "1234567" }))).code, "ACTION_CONFIG_INVALID");
		assert.equal((await completedAction(baseUrl, await save({ wifi0ssid: "Guest", wifi0open: "on" }))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual(snapshot.config.wifiProfiles[0], { ssid: "Guest", password: "", open: true });
		assert.equal((await completedAction(baseUrl, await save({ wifi0ssid: "Guest" }))).code, "ACTION_WIFI_PASSWORD_REQUIRED");
		assert.equal((await completedAction(baseUrl, await save({ wifi0ssid: "Guest", wifi0pass: "secured-secret" }))).success, true);
		snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual(snapshot.config.wifiProfiles[0], { ssid: "Guest", password: "", open: false });

		for (const [field, value] of [["networkMode", "3"], ["networkMode", "2x"], ["heartbeatInterval", "241"], ["heartbeatInterval", "12x"]]) {
			assert.equal((await completedAction(baseUrl, await save({ [field]: value }))).code, "ACTION_CONFIG_INVALID", field);
		}
	});
});

test("v1 through v3 restores preserve target connectivity settings", async () => {
	const vector = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v1.json", import.meta.url), "utf8"));
	const v2 = decryptBackup(Buffer.from(vector.smscfgHex, "hex"), vector.passphrase);
	const versions = [portableV1(), v2, Buffer.from(v2)];
	versions[2].writeUInt16LE(3, 4);
	await withServer(async (baseUrl) => {
		for (const [index, portable] of versions.entries()) {
			const passphrase = `legacy restore passphrase ${index + 1}`;
			const encrypted = encryptBackup(portable, passphrase);
			const save = await request(baseUrl, "/save", {
				method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ wifi0ssid: `Before restore ${index + 1}`, wifi0pass: "wifi-secret", networkMode: "2", heartbeatEnable: "on", heartbeatInterval: "24" })
			});
			assert.equal((await completedAction(baseUrl, save)).success, true);
			const started = await request(baseUrl, "/api/config/restore/start", {
				method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ size: String(encrypted.length) })
			});
			const uploadId = (await started.json()).data.uploadId;
			assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${uploadId}&offset=0`, {
				method: "POST", ...base64Body(encrypted)
			})).status, 200);
			const restored = await request(baseUrl, `/api/config/restore/finish?id=${uploadId}`, {
				method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ passphrase })
			});
			assert.equal((await completedAction(baseUrl, restored)).success, true);
			const snapshot = await (await request(baseUrl, "/api/config")).json();
			assert.deepEqual(snapshot.config.wifiProfiles[0], { ssid: `Before restore ${index + 1}`, password: "", open: false });
			assert.deepEqual({ mode: snapshot.config.networkMode, enabled: snapshot.config.heartbeatEnable, hours: snapshot.config.heartbeatInterval }, { mode: 2, enabled: true, hours: 24 });
		}
	});
});

test("the configuration envelope golden vector binds the full little-endian header", async () => {
	const vector = JSON.parse(await readFile(new URL("./fixtures/config-envelope-v1.json", import.meta.url), "utf8"));
	const encrypted = Buffer.from(vector.smscfgHex, "hex");
	const plaintext = decryptBackup(encrypted, vector.passphrase);
	assert.equal(plaintext.toString("hex"), vector.plaintextHex);
	assert.equal(plaintext.subarray(0, 4).toString(), "CFG2");
	assert.equal(plaintext.readUInt16LE(4), 2);
	assert.equal(plaintext.readUInt32LE(16), crc32(plaintext.subarray(20)));
	const tampered = Buffer.from(encrypted);
	tampered[43] ^= 1;
	assert.throws(() => decryptBackup(tampered, vector.passphrase));
});

test("configuration exports require CSRF and only keep the latest pending file", async () => {
	await withServer(async (baseUrl) => {
		async function startExport(passphrase) {
			const accepted = await request(baseUrl, "/api/config/export", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ passphrase })
			});
			const jobId = (await accepted.json()).data.jobId;
			return (await (await request(baseUrl, `/api/jobs?id=${jobId}`)).json()).result.data.exportId;
		}

		const firstId = await startExport("first correct horse battery staple");
		const secondId = await startExport("second correct horse battery staple");
		assert.equal((await request(baseUrl, `/api/config/export?id=${firstId}`)).status, 404);
		assert.equal((await fetch(`${baseUrl}/api/config/export?id=${secondId}`, { headers: { Authorization: auth } })).status, 403);
		assert.equal((await request(baseUrl, `/api/config/export?id=${secondId}`)).status, 200);
	});
});

test("clearing all accounts does not restore the default credentials", async () => {
	await withServer(async (baseUrl) => {
		const headers = { Authorization: auth, "X-CSRF-Token": "mock-csrf-token", "Content-Type": "application/x-www-form-urlencoded" };
		const changed = await fetch(`${baseUrl}/save`, {
			method: "POST",
			headers,
			body: new URLSearchParams({ account0user: "operator", account0pass: "secret" })
		});
		assert.equal(changed.status, 202);

		const operatorAuth = `Basic ${Buffer.from("operator:secret").toString("base64")}`;
		const cleared = await fetch(`${baseUrl}/save`, {
			method: "POST",
			headers: { Authorization: operatorAuth, "X-CSRF-Token": "mock-csrf-token", "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ account0user: "", account0pass: "" })
		});
		assert.equal(cleared.status, 400);
		assert.equal((await cleared.json()).code, "ACTION_CONFIG_ACCOUNT_REQUIRED");
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: operatorAuth } })).status, 200);
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: auth } })).status, 401);
	});
});

test("request and UTF-8 field limits reject before authentication or mutation", async () => {
	await withServer(async (baseUrl) => {
		const oversizedRequestLine = await fetch(`${baseUrl}/${"a".repeat(2050)}`);
		assert.equal(oversizedRequestLine.status, 414);
		assert.equal(oversizedRequestLine.headers.get("cache-control"), "no-store");

		const oversizedHeader = await fetch(`${baseUrl}/api/config`, {
			headers: { Authorization: `Basic ${"a".repeat(8200)}` }
		});
		assert.equal(oversizedHeader.status, 431);
		assert.equal(oversizedHeader.headers.get("cache-control"), "no-store");
		assert.equal(oversizedHeader.headers.get("connection"), "close");

		const oversizedBody = await fetch(`${baseUrl}/save`, {
			method: "POST",
			headers: { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" },
			body: `smtpServer=${"a".repeat(16400)}`
		});
		assert.equal(oversizedBody.status, 413);

		const rejected = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ smtpServer: "changed.example", smtpUser: "界".repeat(85) })
		});
		assert.equal(rejected.status, 400);
		assert.deepEqual(await rejected.json(), {
			success: false, code: "ACTION_INPUT_TOO_LONG", data: {}, detail: "smtpUser"
		});
		const snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(snapshot.config.smtpServer, "");

		const accepted = await request(baseUrl, "/sendsms", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ phone: "+886900000000", content: "界".repeat(682) })
		});
		assert.equal(accepted.status, 202);
		const tooLong = await request(baseUrl, "/sendsms", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ phone: "+886900000000", content: "界".repeat(683) })
		});
		assert.equal(tooLong.status, 400);
		assert.equal((await tooLong.json()).detail, "content");

		const rejectedCommand = await request(baseUrl, "/at?cmd=AT%2BCMGS%3D1");
		assert.equal(rejectedCommand.status, 400);
		assert.equal((await rejectedCommand.json()).code, "ACTION_AT_REJECTED");

		const oversizedRestore = await request(baseUrl, "/api/config/restore/start", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ size: "32829" })
		});
		assert.equal(oversizedRestore.status, 400);
		const boundedRestore = await request(baseUrl, "/api/config/restore/start", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ size: "60" })
		});
		const boundedId = (await boundedRestore.json()).data.uploadId;
		assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${boundedId}&offset=0`, {
			method: "POST", ...base64Body(Buffer.alloc(61))
		})).status, 400);
		const oversizedOta = await request(baseUrl, "/api/ota/start", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ manifest: '{"format":1,"size":1966081}', signature: "3000" })
		});
		assert.equal(oversizedOta.status, 400);
	});
});

test("the mock implements the documented API", async () => {
	await withServer(async (baseUrl) => {
		const unauthorized = await fetch(`${baseUrl}/api/config`);
		assert.equal(unauthorized.status, 401);
		assert.match(unauthorized.headers.get("www-authenticate"), /^Basic /);

		const snapshotResponse = await request(baseUrl, "/api/config");
		assert.equal(snapshotResponse.status, 200);
		const snapshot = await snapshotResponse.json();
		assert.equal(snapshot.config.deviceName, "SMS Forwarder 000001");
		assert.equal(snapshot.config.hostname, "sms-forwarder-000001");
			assert.equal(snapshot.config.notificationLocale, "zh-TW");
			assert.equal(snapshot.status.apMode, true);
			assert.equal(snapshot.status.ip, "192.168.4.1");
			assert.equal(snapshot.config.pushChannels.length, 5);
		assert.equal(snapshot.config.webAccounts.length, 10);
		assert.deepEqual(snapshot.config.webAccounts[0], { username: "admin", password: "" });
		assert.equal(snapshot.config.smtpPass, "");
		assert.equal(snapshot.csrfToken, "mock-csrf-token");
		assert.deepEqual(snapshot.config.pushChannels[0], {
			enabled: false, type: 1, name: "Channel 1", url: "", urlSet: false,
			key1: "", key1Set: false, key2: "", key2Set: false,
			customBody: "", customBodySet: false, titleTemplate: "", bodyTemplate: ""
		});
		const invalidSave = await request(baseUrl, "/save", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ hostname: "INVALID_HOST" })
		});
		assert.equal(invalidSave.status, 202);
		assert.equal((await completedAction(baseUrl, invalidSave)).code, "ACTION_CONFIG_INVALID");
		assert.equal((await (await request(baseUrl, "/api/config")).json()).config.hostname, "sms-forwarder-000001");

		const form = new URLSearchParams({
			smtpServer: "smtp.example.com",
			smtpPort: "465",
			smtpUser: "sender@example.com",
				smtpPass: "secret",
				smtpSendTo: "recipient@example.com",
				wifi0ssid: "Office WiFi",
				wifi0pass: "wifi-secret",
				networkMode: "2",
				heartbeatEnable: "on",
				heartbeatInterval: "12",
			push0en: "on",
			push0type: "1",
			push0name: "Primary",
			push0url: "https://example.com/hook",
			push0key1: "",
			push0key2: "",
			push0body: ""
		});
		const saved = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: form
		});
		assert.deepEqual(await completedAction(baseUrl, saved), { success: true, code: "ACTION_CONFIG_SAVED", data: {}, detail: "" });

		const changed = await (await request(baseUrl, "/api/config")).json();
		assert.equal(changed.config.smtpServer, "smtp.example.com");
		assert.equal(changed.status.emailConfigured, true);
		assert.equal(changed.status.enabledPushChannels, 1);

		const accountSaved = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ account1user: "operator", account1pass: "secret" })
		});
		assert.equal((await completedAction(baseUrl, accountSaved)).success, true);
		const operatorAuth = `Basic ${Buffer.from("operator:secret").toString("base64")}`;
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: operatorAuth } })).status, 200);

		const calls = [
			["/sendsms", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ phone: "+886900000000", content: "Hello" }) }],
			["/ping", { method: "POST" }],
			["/query?type=ati"],
			["/flight?action=query"],
			["/at?cmd=AT%2BCSQ"],
			["/modem?action=signal"],
			["/wifi?action=restart"]
		];
		for (const [path, init] of calls) {
			const response = await request(baseUrl, path, init);
			assert.equal(response.status, 202, path);
			const body = await completedAction(baseUrl, response);
			assert.equal(typeof body.success, "boolean", path);
			assert.match(body.code, /^ACTION_/i, path);
			assert.equal(typeof body.data, "object", path);
			assert.equal(typeof body.detail, "string", path);
		}

		assert.deepEqual((await completedAction(baseUrl, await request(baseUrl, "/query?type=signal"))).data, {
			rsrpDbm: -82,
			rsrqDb: -9.5,
			cesq: "99,99,255,255,20,58"
		});
		assert.deepEqual((await completedAction(baseUrl, await request(baseUrl, "/query?type=wifi"))).data, {
			wifiStatus: 3,
			ssid: "MockNetwork",
			rssiDbm: -54,
			ip: "192.168.1.50",
			gateway: "192.168.1.1",
			netmask: "255.255.255.0",
			dns: "192.168.1.1",
			mac: "02:00:00:00:00:01",
			bssid: "02:00:00:00:00:02",
			channel: 6
		});

		const logs = await (await request(baseUrl, "/log?limit=2")).json();
		assert.ok(Array.isArray(logs.entries));
		assert.equal(logs.entries.length, 2);
		assert.equal(typeof logs.entries[0].id, "number");
		assert.equal(typeof logs.entries[0].message, "string");
		assert.equal(typeof logs.nextCursor, "number");
		assert.equal(typeof logs.hasMore, "boolean");
		const olderLogs = await (await request(baseUrl, `/log?limit=2&cursor=${logs.nextCursor}`)).json();
		assert.ok(olderLogs.entries.every((entry) => entry.id < logs.nextCursor));

		const exportStart = await request(baseUrl, "/api/config/export", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ passphrase: "correct horse battery staple" })
		});
		assert.equal(exportStart.status, 202);
		const acceptedExport = await exportStart.json();
		const exportJob = await (await request(baseUrl, `/api/jobs?id=${acceptedExport.data.jobId}`)).json();
		assert.equal(exportJob.state, "succeeded");
		assert.notEqual(exportJob.result.data.exportId, acceptedExport.data.jobId);
		const exportPath = `/api/config/export?id=${exportJob.result.data.exportId}`;
		const exported = new Uint8Array(await (await request(baseUrl, exportPath)).arrayBuffer());
		assert.equal((await request(baseUrl, exportPath)).status, 404);
		const portable = decryptBackup(exported, "correct horse battery staple");
		assert.equal(portable.subarray(0, 4).toString(), "CFG2");
			assert.equal(portable.readUInt16LE(4), 4);
		assert.equal(portable.readUInt32LE(8), 0);
		assert.equal(portable.readUInt32LE(12), portable.length - 20);
		assert.equal(portable.readUInt32LE(16), crc32(portable.subarray(20)));
		assert.throws(() => {
			const tamperedHeader = Buffer.from(exported);
			tamperedHeader[43] ^= 1;
			decryptBackup(tamperedHeader, "correct horse battery staple");
		});

		const targetChanged = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					deviceName: "Target gateway", hostname: "target-gateway",
					notificationLocale: "en", smtpServer: "changed.example.com",
					wifi0ssid: "Target WiFi", wifi0pass: "target-secret", networkMode: "0",
					heartbeatInterval: "24"
			})
		});
		assert.equal((await completedAction(baseUrl, targetChanged)).success, true);
		const invalidPortable = Buffer.from(portable);
		let localeOffset = 24;
		for (let field = 0; field < 2; field += 1) localeOffset += 2 + invalidPortable.readUInt16LE(localeOffset);
		assert.equal(invalidPortable.readUInt16LE(localeOffset), 5);
		invalidPortable.write("bad!!", localeOffset + 2);
		invalidPortable.writeUInt32LE(crc32(invalidPortable.subarray(20)), 16);
		const invalidEncrypted = encryptBackup(invalidPortable, "correct horse battery staple");
		const invalidStart = await request(baseUrl, "/api/config/restore/start", {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ size: String(invalidEncrypted.length) })
		});
		const invalidId = (await invalidStart.json()).data.uploadId;
		assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${invalidId}&offset=0`, {
			method: "POST", ...base64Body(invalidEncrypted)
		})).status, 200);
		const invalidFinish = await request(baseUrl, `/api/config/restore/finish?id=${invalidId}`, {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ passphrase: "correct horse battery staple" })
		});
		assert.equal(invalidFinish.status, 202);
		const invalidJobId = (await invalidFinish.json()).data.jobId;
		const invalidJob = await (await request(baseUrl, `/api/jobs?id=${invalidJobId}`)).json();
		assert.equal(invalidJob.state, "failed");
		assert.equal(invalidJob.result.code, "ACTION_CONFIG_RESTORE_INVALID");
		const unchanged = await (await request(baseUrl, "/api/config")).json();
		assert.equal(unchanged.config.notificationLocale, "en");
		assert.equal(unchanged.config.smtpServer, "changed.example.com");

		const restoreStart = await request(baseUrl, "/api/config/restore/start", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ size: String(exported.length) })
		});
		assert.equal(restoreStart.status, 201);
		const restoreId = (await restoreStart.json()).data.uploadId;
		assert.equal((await request(baseUrl, `/api/config/restore/chunk?id=${restoreId}&offset=0`, {
			method: "POST", ...base64Body(exported)
		})).status, 200);
		const restore = await request(baseUrl, `/api/config/restore/finish?id=${restoreId}`, {
			method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ passphrase: "correct horse battery staple" })
		});
		assert.equal(restore.status, 202);
		const acceptedRestore = await restore.json();
		const restoredJob = await (await request(baseUrl, `/api/jobs?id=${acceptedRestore.data.jobId}`)).json();
		assert.equal(restoredJob.state, "succeeded");
		assert.equal(restoredJob.result.code, "ACTION_CONFIG_RESTORED");
		const restoredSnapshot = await (await request(baseUrl, "/api/config")).json();
		assert.equal(restoredSnapshot.config.deviceName, "Target gateway");
		assert.equal(restoredSnapshot.config.hostname, "target-gateway");
			assert.equal(restoredSnapshot.config.notificationLocale, "zh-TW");
			assert.equal(restoredSnapshot.config.smtpServer, "smtp.example.com");
			assert.deepEqual(restoredSnapshot.config.wifiProfiles[0], { ssid: "Office WiFi", password: "", open: false });
			assert.equal(restoredSnapshot.config.networkMode, 2);
			assert.equal(restoredSnapshot.config.heartbeatEnable, true);
			assert.equal(restoredSnapshot.config.heartbeatInterval, 12);
		assert.equal(restoredSnapshot.config.webAccounts[1].username, "operator");
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: operatorAuth } })).status, 200);

		const otaStart = await request(baseUrl, "/api/ota/start", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ manifest: '{"format":1,"size":3}', signature: "3000" })
		});
		assert.equal(otaStart.status, 201);
		const otaId = (await otaStart.json()).data.uploadId;
		await request(baseUrl, `/api/ota/chunk?id=${otaId}&offset=0`, {
			method: "POST", ...base64Body(new Uint8Array([0, 1, 0]))
		});
		const ota = await request(baseUrl, `/api/ota/finish?id=${otaId}`, { method: "POST" });
		assert.equal(ota.status, 202);
		const acceptedOta = await ota.json();
		assert.equal(acceptedOta.code, "ACTION_JOB_ACCEPTED");
		const otaJob = await (await request(baseUrl, `/api/jobs?id=${acceptedOta.data.jobId}`)).json();
		assert.equal(otaJob.state, "succeeded");
		assert.equal(otaJob.result.code, "ACTION_OTA_READY");

		const openApi = await (await request(baseUrl, "/openapi.json")).json();
		assert.equal(openApi.openapi, "3.1.0");

		const expectedHtml = await readFile(`${process.env.WEB_ROOT}/index.html`, "utf8");
		for (const path of ["/", "/tools", "/sms"]) {
			const response = await request(baseUrl, path);
			assert.equal(response.status, 200);
			assert.equal(await response.text(), expectedHtml);
		}
	});
});
