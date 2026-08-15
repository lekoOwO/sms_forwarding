import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createApp } from "../server.mjs";

const auth = `Basic ${Buffer.from("admin:admin123").toString("base64")}`;

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
		headers: { Authorization: auth, ...init.headers }
	});
}

test("authentication can be disabled for the LAN development server", async () => {
	await withServer(async (baseUrl) => {
		assert.equal((await fetch(`${baseUrl}/api/config`)).status, 200);
	}, { authRequired: false });
});

test("clearing all accounts does not restore the default credentials", async () => {
	await withServer(async (baseUrl) => {
		const headers = { Authorization: auth, "Content-Type": "application/x-www-form-urlencoded" };
		const changed = await fetch(`${baseUrl}/save`, {
			method: "POST",
			headers,
			body: new URLSearchParams({ account0user: "operator", account0pass: "secret" })
		});
		assert.equal(changed.status, 200);

		const operatorAuth = `Basic ${Buffer.from("operator:secret").toString("base64")}`;
		const cleared = await fetch(`${baseUrl}/save`, {
			method: "POST",
			headers: { Authorization: operatorAuth, "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ account0user: "", account0pass: "" })
		});
		assert.equal(cleared.status, 400);
		assert.equal((await cleared.json()).code, "ACTION_CONFIG_ACCOUNT_REQUIRED");
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: operatorAuth } })).status, 200);
		assert.equal((await fetch(`${baseUrl}/api/config`, { headers: { Authorization: auth } })).status, 401);
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
		assert.equal(snapshot.config.pushChannels.length, 5);
		assert.equal(snapshot.config.webAccounts.length, 10);
		assert.deepEqual(snapshot.config.webAccounts[0], { username: "admin", password: "" });
		assert.equal(snapshot.config.smtpPass, "");

		const form = new URLSearchParams({
			smtpServer: "smtp.example.com",
			smtpPort: "465",
			smtpUser: "sender@example.com",
			smtpPass: "secret",
			smtpSendTo: "recipient@example.com",
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
		assert.deepEqual(await saved.json(), { success: true, code: "ACTION_CONFIG_SAVED", data: {}, detail: "" });

		const changed = await (await request(baseUrl, "/api/config")).json();
		assert.equal(changed.config.smtpServer, "smtp.example.com");
		assert.equal(changed.status.emailConfigured, true);
		assert.equal(changed.status.enabledPushChannels, 1);

		const accountSaved = await request(baseUrl, "/save", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ account1user: "operator", account1pass: "secret" })
		});
		assert.equal((await accountSaved.json()).success, true);
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
			assert.equal(response.status, 200, path);
			const body = await response.json();
			assert.equal(typeof body.success, "boolean", path);
			assert.match(body.code, /^ACTION_/i, path);
			assert.equal(typeof body.data, "object", path);
			assert.equal(typeof body.detail, "string", path);
		}

		assert.deepEqual((await (await request(baseUrl, "/query?type=signal")).json()).data, {
			rsrpDbm: -82,
			rsrqDb: -9.5,
			cesq: "99,99,255,255,20,58"
		});
		assert.deepEqual((await (await request(baseUrl, "/query?type=wifi")).json()).data, {
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

		const logs = await (await request(baseUrl, "/log")).json();
		assert.ok(Array.isArray(logs));
		assert.ok(logs.length > 2);

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
