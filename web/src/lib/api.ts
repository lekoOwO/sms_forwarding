import type { ActionResult, DeviceSnapshot, Job, LogPage } from "$lib/types";
import { CONFIG_MIME_TYPE } from "$lib/config-schema.generated";

let csrfToken = "";
export const demoMode = import.meta.env.VITE_DEMO_MODE === "1";
const demoStartedAt = Date.now();
const demoConfig: DeviceSnapshot["config"] = {
	deviceName: "Lobby SMS Gateway",
	hostname: "sms-forwarder-demo",
	notificationLocale: "zh-TW",
	emailEnabled: true,
	pushEnabled: true,
	webAccounts: Array.from({ length: 10 }, (_, index) => ({ username: index === 0 ? "admin" : "", password: "" })),
	smtpServer: "smtp.example.com", smtpPort: 465, smtpUser: "gateway@example.com", smtpPass: "", smtpSendTo: "ops@example.com",
	adminPhone: "+886900000000", numberBlackList: "", forwardRules: "kw\tOTP\temail",
	wifiProfiles: Array.from({ length: 5 }, (_, index) => ({ ssid: index === 0 ? "DemoNetwork" : "", password: "", open: false })),
	networkMode: 0, heartbeatEnable: true, heartbeatInterval: 6,
	kaEnabled: false, kaIntervalDays: 175, kaTrafficKB: 1,
	pushChannels: Array.from({ length: 5 }, (_, index) => ({
		enabled: index === 0, type: 1, name: `Channel ${index + 1}`, url: "", urlSet: index === 0,
		key1: "", key1Set: false, key2: "", key2Set: false, customBody: "", customBodySet: false,
		titleTemplate: "", bodyTemplate: ""
	}))
};
const demoLogs = ["Demo device started", "WiFi connected: DemoNetwork", "Cellular modem ready"];

function demoSnapshot(): DeviceSnapshot {
	return {
		csrfToken: "demo",
		status: {
			ip: "192.168.1.50", wifiSsid: "DemoNetwork", apMode: false, freeHeapKb: 247,
			uptimeSeconds: Math.floor((Date.now() - demoStartedAt) / 1000), modemReady: true,
			emailConfigured: true, enabledPushChannels: demoConfig.pushChannels.filter((channel) => channel.enabled).length,
			firmwareVersion: "1"
		},
		config: structuredClone(demoConfig)
	};
}

function forwardRulesValid(rules: string) {
	for (const rawLine of rules.split("\n")) {
		const [type, pattern, , enabled = "1"] = rawLine.trim().split("\t");
		if (enabled.trim() === "0" || !pattern || !["from", "re"].includes(type)) continue;
		if (/(^|[^\\])(?:\\\\)*\(\?/.test(pattern)) return false;
		try { new RegExp(pattern, "i"); }
		catch { return false; }
	}
	return true;
}

function demoResponse<T>(path: string, init?: RequestInit): T {
	if (path === "/api/config") return demoSnapshot() as T;
	if (path.startsWith("/log?")) return {
		entries: demoLogs.map((message, index) => ({ id: index + 1, message })), nextCursor: 1, hasMore: false
	} as T;
	if (path === "/save" && init?.body instanceof URLSearchParams) {
		const form = init.body;
		for (const field of ["emailEnabled", "pushEnabled"] as const) {
			if (!form.has(field)) continue;
			const value = form.get(field);
			if (value !== "0" && value !== "1") return {
					success: false, code: "ACTION_CONFIG_INVALID", data: {}, detail: field
				} as T;
		}
		const forwardRules = form.get("forwardRules");
		if (forwardRules !== null && !forwardRulesValid(forwardRules)) return {
			success: false, code: "ACTION_CONFIG_INVALID", data: {}, detail: "forwardRules"
		} as T;
		for (const [key, value] of init.body) {
			if (key in demoConfig && !["webAccounts", "pushChannels", "wifiProfiles", "emailEnabled", "pushEnabled", "networkMode", "heartbeatEnable", "heartbeatInterval", "kaEnabled", "kaIntervalDays", "kaTrafficKB"].includes(key)) (demoConfig as unknown as Record<string, unknown>)[key] = value;
		}
		if (form.has("emailEnabled")) demoConfig.emailEnabled = form.get("emailEnabled") === "1";
		if (form.has("pushEnabled")) demoConfig.pushEnabled = form.get("pushEnabled") === "1";
		if (init.body.has("networkMode")) demoConfig.networkMode = Number(init.body.get("networkMode"));
		if (init.body.has("heartbeatInterval")) {
			demoConfig.heartbeatEnable = init.body.has("heartbeatEnable");
			demoConfig.heartbeatInterval = Number(init.body.get("heartbeatInterval"));
		}
		if (["kaEnabled", "kaIntervalDays", "kaTrafficKB"].some((field) => form.has(field))) {
			demoConfig.kaEnabled = form.has("kaEnabled");
			if (form.has("kaIntervalDays")) demoConfig.kaIntervalDays = Number(form.get("kaIntervalDays"));
			if (form.has("kaTrafficKB")) demoConfig.kaTrafficKB = Number(form.get("kaTrafficKB"));
		}
		for (let index = 0; index < demoConfig.wifiProfiles.length; index += 1) {
			const ssidKey = `wifi${index}ssid`;
			const passKey = `wifi${index}pass`;
			const openKey = `wifi${index}open`;
			if (!init.body.has(ssidKey) && !init.body.has(passKey) && !init.body.has(openKey)) continue;
			const profile = demoConfig.wifiProfiles[index];
			const ssid = init.body.get(ssidKey) ?? profile.ssid;
			profile.ssid = ssid;
			if (!ssid || init.body.has(openKey)) {
				profile.password = "";
				profile.open = Boolean(ssid);
			} else if (init.body.get(passKey)) {
				profile.password = String(init.body.get(passKey));
				profile.open = false;
			}
		}
		for (let index = 0; index < demoConfig.pushChannels.length; index += 1) {
			const prefix = `push${index}`;
			if (!["en", "type", "name", "url", "key1", "key2", "body", "title", "template"].some((suffix) => form.has(`${prefix}${suffix}`))) continue;
			const channel = demoConfig.pushChannels[index];
			const type = Number(init.body.get(`${prefix}type`) ?? channel.type);
			if (type !== channel.type) {
				channel.url = ""; channel.urlSet = false;
				channel.key1 = ""; channel.key1Set = false;
				channel.key2 = ""; channel.key2Set = false;
				channel.customBody = ""; channel.customBodySet = false;
			}
			channel.enabled = init.body.has(`${prefix}en`);
			channel.type = type;
			channel.name = init.body.get(`${prefix}name`) || `Channel ${index + 1}`;
			for (const [suffix, field, setField] of [
				["url", "url", "urlSet"], ["key1", "key1", "key1Set"],
				["key2", "key2", "key2Set"], ["body", "customBody", "customBodySet"]
			] as const) {
				if (init.body.get(`${prefix}${suffix}`)) {
					channel[field] = "";
					channel[setField] = true;
				}
			}
			channel.titleTemplate = init.body.get(`${prefix}title`) ?? "";
			channel.bodyTemplate = init.body.get(`${prefix}template`) ?? "";
		}
	}
	if (path === "/ping") return {
		success: false, code: "ACTION_PING_UNSUPPORTED", data: {}, detail: ""
	} as T;
	const data = path.includes("ati") ? { manufacturer: "Demo Telecom", model: "Demo LTE-C3", revision: "1.0.0" }
		: path.includes("signal") ? { signalDbm: -82, rssi: 16, ber: 0 } : {};
	const code = path === "/save" ? "ACTION_CONFIG_SAVED" : path === "/sendsms" ? "ACTION_SMS_SENT"
		: path.startsWith("/query") ? "ACTION_QUERY_OK"
		: path.startsWith("/at") ? "ACTION_AT_OK" : "ACTION_MODEM_OK";
	return { success: true, code, data, detail: "" } as T;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
	if (demoMode) return demoResponse<T>(path, init);
	const response = await fetch(path, {
		...init,
		headers: {
			Accept: "application/json",
			...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
			...init?.headers
		}
	});
	const data = await response.json().catch(() => undefined);
	if (!response.ok && !(data && typeof data === "object" && "code" in data)) {
		throw new Error(`HTTP ${response.status}`);
	}
	return data as T;
}

export async function loadSnapshot(): Promise<DeviceSnapshot> {
	const snapshot = await requestJson<DeviceSnapshot>("/api/config");
	csrfToken = snapshot.csrfToken;
	return snapshot;
}

export function runAction(path: string, init?: RequestInit): Promise<ActionResult> {
	return requestJson<ActionResult>(path, init);
}

export async function exportEncryptedConfig(passphrase: string): Promise<Uint8Array> {
	const accepted = await postForm("/api/config/export", { passphrase });
	if (!accepted.success) throw new Error(accepted.code);
	const jobId = Number(accepted.data.jobId);
	if (!Number.isInteger(jobId)) throw new Error("Export did not return a job id.");
	const completed = await waitForJob(jobId);
	if (!completed.success) throw new Error(completed.code);
	const exportId = Number(completed.data.exportId);
	const response = await fetch(`/api/config/export?id=${exportId}`, {
		headers: { Accept: CONFIG_MIME_TYPE, "X-CSRF-Token": csrfToken }
	});
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
	return new Uint8Array(await response.arrayBuffer());
}

function otaPayload(file: Uint8Array) {
	const magic = new TextEncoder().encode("SMSOTA1\n");
	if (file.length < 14 || !magic.every((byte, index) => file[index] === byte)) {
		throw new Error("This is not a supported .smsota package.");
	}
	const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
	const manifestLength = view.getUint32(8);
	const signatureLengthOffset = 12 + manifestLength;
	if (manifestLength === 0 || signatureLengthOffset + 2 > file.length) throw new Error("The .smsota package is truncated.");
	const signatureLength = view.getUint16(signatureLengthOffset);
	const firmwareOffset = signatureLengthOffset + 2 + signatureLength;
	if (signatureLength === 0 || firmwareOffset >= file.length) throw new Error("The .smsota package is truncated.");
	return {
		manifest: new TextDecoder("utf-8", { fatal: true }).decode(file.slice(12, signatureLengthOffset)),
		signature: [...file.slice(signatureLengthOffset + 2, firmwareOffset)]
			.map((byte) => byte.toString(16).padStart(2, "0")).join(""),
		firmware: file.slice(firmwareOffset)
	};
}

function base64Chunk(bytes: Uint8Array) {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

export async function uploadOta(file: Uint8Array): Promise<ActionResult> {
	const payload = otaPayload(file);
	const start = await postForm("/api/ota/start", { manifest: payload.manifest, signature: payload.signature });
	if (!start.success) return start;
	const id = Number(start.data.uploadId);
	if (!Number.isInteger(id)) throw new Error("Upload session did not return an id.");
	for (let offset = 0; offset < payload.firmware.length; offset += 8192) {
		const body = base64Chunk(payload.firmware.slice(offset, offset + 8192));
		const response = await runAction(`/api/ota/chunk?id=${id}&offset=${offset}`, {
			method: "POST",
			headers: { "Content-Type": "text/plain;charset=UTF-8" },
			body
		});
		if (!response.success) return response;
	}
	return runAction(`/api/ota/finish?id=${id}`, { method: "POST" });
}

export async function uploadRestore(bytes: Uint8Array, passphrase: string): Promise<ActionResult> {
	const start = await postForm("/api/config/restore/start", { size: bytes.length });
	if (!start.success) return start;
	const id = Number(start.data.uploadId);
	if (!Number.isInteger(id)) throw new Error("Upload session did not return an id.");
	for (let offset = 0; offset < bytes.length; offset += 8192) {
		const body = base64Chunk(bytes.slice(offset, offset + 8192));
		const chunk = await runAction(`/api/config/restore/chunk?id=${id}&offset=${offset}`, {
			method: "POST",
			headers: { "Content-Type": "text/plain;charset=UTF-8" },
			body
		});
		if (!chunk.success) return chunk;
	}
	return postForm(`/api/config/restore/finish?id=${id}`, { passphrase });
}

export async function waitForJob(id: number): Promise<ActionResult> {
	for (let attempt = 0; attempt < 120; attempt += 1) {
		const job = await requestJson<Job>(`/api/jobs?id=${id}`);
		if (job.state === "succeeded" || job.state === "failed") {
			if (!job.result) throw new Error("Completed job did not return a result.");
			return job.result;
		}
		await new Promise((resolve) => window.setTimeout(resolve, 750));
	}
	throw new Error("Job polling timed out.");
}

export async function waitForAccepted(result: ActionResult): Promise<ActionResult> {
	if (result.code !== "ACTION_JOB_ACCEPTED") return result;
	const jobId = Number(result.data.jobId);
	if (!Number.isInteger(jobId)) throw new Error("Accepted job did not return a job id.");
	return waitForJob(jobId);
}

export function postForm(path: string, values: Record<string, string | number | boolean>) {
	const body = new URLSearchParams();
	for (const [key, value] of Object.entries(values)) {
		if (typeof value === "boolean") {
			if (value) body.set(key, "on");
		} else {
			body.set(key, String(value));
		}
	}
	return runAction(path, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
		body
	});
}

export async function loadLogs(cursor?: number): Promise<LogPage> {
	const query = new URLSearchParams({ limit: "50" });
	if (cursor !== undefined) query.set("cursor", String(cursor));
	return requestJson<LogPage>(`/log?${query}`);
}
