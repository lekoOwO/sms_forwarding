import assert from "node:assert/strict";
import test from "node:test";
import { request as httpRequest } from "node:http";
import { createApp } from "../server.mjs";

test("keepalive uses its own certificate target, rejects HTTP and supports cancellation", async () => {
		let clock = Date.now();
		const server = createApp({ jobDelayMs: 20, now: () => clock }).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	const base = `http://127.0.0.1:${server.address().port}`;
	const headers = { Authorization: `Basic ${Buffer.from("admin:admin123").toString("base64")}`, "X-CSRF-Token": "mock-csrf-token" };
	const request = (path, init = {}) => fetch(base + path, { ...init, headers: { ...headers, ...init.headers } });
	async function finish(response) {
		let data = await response.json();
		if (data.code !== "ACTION_JOB_ACCEPTED") return data;
		const id = data.data.jobId;
		for (let i = 0; i < 100; i++) {
			data = await (await request(`/api/jobs?id=${id}`)).json();
			if (data.state === "succeeded" || data.state === "failed") return data.result;
			await new Promise((resolve) => setTimeout(resolve, 5));
		}
		throw new Error("job did not finish");
	}
	try {
		assert.equal((await request("/api/keepalive")).status, 200);
		for (const query of ["unknown=run", "action=run&action=cancel", "action=run&other=x"]) {
			assert.equal((await request(`/api/keepalive?${query}`, { method: "POST" })).status, 400);
		}
		const transferStatus = await new Promise((resolve, reject) => {
			const req = httpRequest(`${base}/api/keepalive?action=run`, { method: "POST", headers: { ...headers, "Transfer-Encoding": "chunked" } }, (response) => {
				response.resume(); response.on("end", () => resolve(response.statusCode));
			});
			req.on("error", reject); req.end();
		});
		assert.equal(transferStatus, 400);
		assert.equal((await request("/api/keepalive/ca/status?channel=0")).status, 400);
		assert.equal((await request("/api/push/ca/status?channel=5")).status, 400);
		const save = (url, enabled = false) => request("/save", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ kaUrl: url, kaIntervalDays: "175", kaTrafficKB: "1", ...(enabled ? { kaEnabled: "on" } : {}) }) });
		assert.equal((await finish(await save("http://example.test/file", true))).success, false);
		assert.equal((await finish(await save("https://example.test/file"))).success, true);
		const probe = await finish(await request("/api/keepalive/ca/probe", { method: "POST" }));
		assert.equal(probe.code, "PUSH_CA_PROBE_READY");
		const cert = Uint8Array.from([0x30, 0x01, 0x00]);
		const install = (path) => request(path, { method: "POST", headers: { "Content-Type": "application/pkix-cert" }, body: cert });
		assert.equal((await install(`/api/push/ca/install?channel=0&nonce=${probe.data.nonce}`)).status, 409);
		const ownProbe = await finish(await request("/api/keepalive/ca/probe", { method: "POST" }));
		assert.equal((await finish(await install(`/api/keepalive/ca/install?nonce=${ownProbe.data.nonce}`))).success, true);
		assert.equal((await (await request("/api/keepalive/ca/status")).json()).data.configured, true);
			assert.equal((await (await request("/api/push/ca/status?channel=0")).json()).data.configured, false);
			clock += 60001; // Expire completed jobs before exercising another provisioning sequence.
		assert.equal((await finish(await save("https://example.test/other"))).success, true);
		assert.equal((await (await request("/api/keepalive/ca/status")).json()).data.configured, true);
		const stale = await finish(await request("/api/keepalive/ca/probe", { method: "POST" }));
		assert.equal((await finish(await save("https://different.test/file"))).success, true);
		assert.equal((await (await request("/api/keepalive/ca/status")).json()).data.configured, false);
		assert.equal((await install(`/api/keepalive/ca/install?nonce=${stale.data.nonce}`)).status, 409);
		const fresh = await finish(await request("/api/keepalive/ca/probe", { method: "POST" }));
		assert.equal((await finish(await install(`/api/keepalive/ca/install?nonce=${fresh.data.nonce}`))).success, true);
		assert.equal((await (await request("/api/keepalive?action=run", { method: "POST" })).json()).success, true);
		assert.equal((await (await request("/api/keepalive?action=cancel", { method: "POST" })).json()).success, true);
		const state = await (await request("/api/keepalive")).json();
		assert.equal(state.cancelRequested, true);
	} finally { await new Promise((resolve) => server.close(resolve)); }
});
