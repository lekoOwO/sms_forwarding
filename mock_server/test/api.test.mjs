import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, pbkdf2Sync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createApp } from "../server.mjs";

const auth = `Basic ${Buffer.from("admin:admin123").toString("base64")}`;
const headers = { Authorization: auth, "X-CSRF-Token": "mock-csrf-token" };

async function withServer(run, options = {}) {
	const server = createApp(options).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	try { await run(`http://127.0.0.1:${server.address().port}`); }
	finally { await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}

function request(baseUrl, path, init = {}) {
	return fetch(`${baseUrl}${path}`, { ...init, headers: { ...headers, ...init.headers } });
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
			kaEnabled: "on", kaIntervalDays: 3650, kaTrafficKB: 10000
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

test("save jobs disable stale unsupported keepalive without changing compatibility values", async () => {
	await withServer(async (baseUrl) => {
		const enabled = await form(baseUrl, "/save", {
			kaEnabled: "on", kaIntervalDays: 200, kaTrafficKB: 4321
		});
		assert.equal(enabled.status, 202);
		assert.equal((await completed(baseUrl, enabled)).code, "ACTION_CONFIG_SAVED");
		let snapshot = await (await request(baseUrl, "/api/config")).json();
		assert.deepEqual([
			snapshot.config.kaEnabled, snapshot.config.kaIntervalDays, snapshot.config.kaTrafficKB
		], [true, 200, 4321]);

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

test("the independent v6 fixture restores, preserves local identity, and matches export bytes", async () => {
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
		assert.equal(response.headers.get("x-config-schema-version"), "6");
		assert.equal(decrypt(await response.arrayBuffer(), fixture.passphrase).toString("hex"), fixture.plaintextHex);
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
		const active = request(baseUrl, "/ping", { method: "POST" });
		await new Promise((resolve) => setTimeout(resolve, 5));
		await assertAction(await form(baseUrl, "/api/ota/start", { manifest: text,
			signature: sign("sha256", Buffer.from(text), privateKey).toString("hex") }), 409, "ACTION_BUSY");
		await active;
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
		assert.equal((await request(baseUrl, `/api/ota/finish?id=${id}`, { method: "POST" })).status, 202);
		await assertAction(await request(baseUrl, "/ping", { method: "POST" }), 409, "ACTION_BUSY");
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
